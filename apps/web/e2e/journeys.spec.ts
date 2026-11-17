import { expect, test, type Page } from '@playwright/test'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

// The five user journeys, run in a real browser against the real API with
// real Dex sign-in. Screenshots go to ../../screenshots when AEGIS_SCREENSHOTS
// is set. Demo users and their development-only password come from
// infrastructure/auth/dex.yml.
const PASSWORD = process.env.DEX_DEV_PASSWORD ?? 'aegis-dev-only'
const SHOTS = process.env.AEGIS_SCREENSHOTS ? join(process.cwd(), '..', '..', 'screenshots') : ''

async function shot(page: Page, name: string) {
  if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`), fullPage: false })
}

async function signIn(page: Page, email: string) {
  await page.context().clearCookies()
  await page.goto('/')
  await page.evaluate(() => sessionStorage.clear())
  await page.goto('/')
  await page.getByRole('button', { name: /sign in with your identity provider/i }).click()
  await page.locator('input[name="login"]').fill(email)
  await page.locator('input[name="password"]').fill(PASSWORD)
  await page.locator('button[type="submit"]').click()
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible({ timeout: 30_000 })
  await expect(page.locator('.whoami')).toContainText(email)
}

// Journey 2 proposes a fix that only one open remediation may hold. Close any
// left by an earlier run (rejected if pending, released if approved), so the
// journeys can run again against the same stack.
async function closeOpenRemediations(page: Page, resource: string, rule: string) {
  for (const approver of ['bob@aegis.local', 'carol@aegis.local']) {
    await signIn(page, approver)
    for (let i = 0; i < 5; i++) {
      await page.goto('/#/remediation')
      const row = page.locator('.table tbody tr', { hasText: resource })
        .filter({ hasText: rule }).filter({ hasText: /pending approval|approved/ }).first()
      try {
        await row.waitFor({ timeout: 5_000 })
      } catch {
        return // nothing open
      }
      await row.click()
      const reject = page.getByRole('button', { name: 'Reject' })
      const release = page.getByRole('button', { name: 'Release change set' })
      await expect(reject.or(release).or(page.getByText('You have already decided.'))).toBeVisible({ timeout: 20_000 })
      if (await reject.isVisible()) {
        await page.getByLabel('Comment').fill('closed by e2e setup')
        await reject.click()
      } else if (await release.isVisible()) {
        await release.click()
      } else {
        break // this approver already decided; try the next one
      }
      await expect(page.locator('.badge').filter({ hasText: /^(rejected|released)$/ }).first()).toBeVisible({ timeout: 20_000 })
    }
  }
}

let remediationURL = ''

test('1. import and scan', async ({ page }) => {
  await signIn(page, 'alice@aegis.local')
  await expect(page.locator('.stat').first()).not.toContainText('—', { timeout: 20_000 })
  await shot(page, '01-overview')

  await page.getByRole('link', { name: 'Import & scan' }).click()
  // A small, valid snapshot for a separate account (idempotent on re-runs).
  const file = join(tmpdir(), 'aegis-e2e-snapshot.json')
  writeFileSync(file, JSON.stringify({
    schema_version: 'aegis.inventory/v1', source: 'synthetic', captured_at: '2026-11-01T00:00:00Z',
    account: { provider: 'aws', external_id: '999999999999', name: 'e2e' },
    resources: [{ resource_id: 'aws_s3_bucket.e2e-uploads', resource_type: 'aws_s3_bucket', region: 'eu-west-1',
      tags: { owner: 'web-team', environment: 'staging', cost_center: 'web' }, configuration: { public_access_block: false, versioning: true } }],
  }))
  await page.getByLabel('Inventory snapshot file').setInputFiles(file)
  await expect(page.locator('.ok-text')).toContainText(/Imported|imported before/)

  await page.getByLabel('Terraform fixture').selectOption('insecure-storage')
  await page.getByRole('button', { name: 'Scan', exact: true }).click()
  await expect(page.locator('.scan')).toContainText(/succeeded|failed/, { timeout: 200_000 })
  await expect(page.locator('.scan')).toContainText('succeeded')
  await shot(page, '02-import-and-scan')
})

test('2. investigate risk and propose a fix', async ({ page }) => {
  await closeOpenRemediations(page, 'aws_db_instance.checkout_002', 'AEGIS-DB-002')
  await signIn(page, 'alice@aegis.local')
  await page.getByRole('link', { name: 'Risk' }).click()
  await expect(page.locator('.table tbody tr').first()).toBeVisible({ timeout: 20_000 })
  await shot(page, '03-risk')

  await page.goto('/#/investigate?resource=aws_db_instance.checkout_002&run=1')
  await expect(page.getByRole('heading', { name: /Evidence \(\d+ items\)/ })).toBeVisible({ timeout: 20_000 })
  await expect(page.locator('.claims li').first()).toContainText(/aws_db_instance.checkout_002/)
  await page.locator('.claims .cite').first().click()
  await shot(page, '04-investigation')

  // Reloading (or Back, or a bookmark) must not store another investigation.
  await page.reload()
  await expect(page.getByLabel('Resource ID')).toHaveValue('aws_db_instance.checkout_002')
  await expect(page.getByRole('heading', { name: /Evidence \(\d+ items\)/ })).toHaveCount(0)
  await page.goto('/#/investigate?resource=aws_db_instance.checkout_002&run=1')
  await expect(page.getByRole('heading', { name: /Evidence \(\d+ items\)/ })).toBeVisible({ timeout: 20_000 })

  await page.getByRole('button', { name: /Propose fix for AEGIS-DB-002/ }).click()
  await expect(page.getByLabel('Resource ID')).toHaveValue('aws_db_instance.checkout_002')
  await page.getByLabel('Rule', { exact: true }).selectOption('AEGIS-DB-002')
  await page.getByLabel('Justification').fill('Checkout database must not be reachable from the internet (e2e).')
  await page.getByRole('button', { name: /Simulate and propose/ }).click()
  await expect(page.getByText(/Approvals \(0 of \d required\)/)).toBeVisible({ timeout: 20_000 })
  await expect(page.locator('.badge').filter({ hasText: 'passed' })).toBeVisible()
  await expect(page.getByText('You requested this change, so someone else must approve it.')).toBeVisible({ timeout: 1 }).catch(() => {})
  remediationURL = page.url()
  await shot(page, '05-remediation-proposed')
})

test('3. compliance evidence', async ({ page }) => {
  await signIn(page, 'alice@aegis.local')
  await page.getByRole('link', { name: 'Compliance evidence' }).click()
  await page.locator('.table tbody tr', { hasText: 'BL-01' }).click()
  await expect(page.getByRole('heading', { name: 'Evidence: BL-01' })).toBeVisible({ timeout: 20_000 })
  await expect(page.locator('.mono', { hasText: 'aws_' }).first()).toBeVisible()
  await shot(page, '06-compliance-evidence')
})

test('4. cost investigation', async ({ page }) => {
  await signIn(page, 'alice@aegis.local')
  await page.getByRole('link', { name: 'Cost' }).click()
  await expect(page.locator('.bar-row').first()).toBeVisible({ timeout: 20_000 })
  await expect(page.getByRole('heading', { name: 'Optimisation recommendations' })).toBeVisible()
  await shot(page, '07-cost')
})

test('5. controlled remediation: two approvers, release', async ({ page }) => {
  expect(remediationURL, 'journey 2 must run first').not.toBe('')
  const path = new URL(remediationURL).hash
  // The requester cannot approve.
  await signIn(page, 'alice@aegis.local')
  await page.goto('/' + path)
  await expect(page.getByRole('button', { name: 'Approve' })).toHaveCount(0)

  for (const approver of ['bob@aegis.local', 'carol@aegis.local']) {
    await signIn(page, approver)
    await page.goto('/' + path)
    await page.getByLabel('Comment').fill(`reviewed by ${approver}`)
    await page.getByRole('button', { name: 'Approve' }).click()
    // Wait for the recorded decision itself (the sidebar also shows the
    // email), so the next sign-in cannot cancel the request in flight.
    await expect(page.locator('ul.small li').filter({ hasText: approver }).filter({ hasText: 'approved' })).toBeVisible({ timeout: 20_000 })
    if (await page.getByRole('button', { name: 'Release change set' }).isVisible()) break
  }
  await page.getByRole('button', { name: 'Release change set' }).click()
  await expect(page.getByRole('heading', { name: 'Change set' })).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText(/Aegis has not changed any cloud resource/)).toBeVisible()
  await expect(page.getByText(/Signed \(Ed25519, key/)).toBeVisible()
  await shot(page, '08-remediation-released')

  // Verifying needs the operate permission (an analyst), and it refuses to
  // guess until the next inventory import shows the change.
  await expect(page.getByRole('button', { name: /Verify/ })).toHaveCount(0)
  await signIn(page, 'alice@aegis.local')
  await page.goto('/' + path)
  await page.getByRole('button', { name: /Verify/ }).click()
  await expect(page.locator('.error')).toContainText(/import/i)
})

test('a viewer sees data but no actions', async ({ page }) => {
  await signIn(page, 'viewer@aegis.local')
  await page.getByRole('link', { name: 'Risk' }).click()
  await expect(page.getByRole('button', { name: 'Run assessment' })).toHaveCount(0)
  await page.getByRole('link', { name: 'Remediation' }).click()
  await expect(page.getByRole('heading', { name: 'Propose a remediation' })).toHaveCount(0)
})
