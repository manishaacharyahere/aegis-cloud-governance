import { expect, test, type Page } from '@playwright/test'
import { join } from 'node:path'

// Records the demo video: one continuous session through the five journeys,
// against the real stack, with captions. Run with AEGIS_DEMO=1; the video is
// written to ../../demo/. Not part of the normal test run.
test.skip(!process.env.AEGIS_DEMO, 'set AEGIS_DEMO=1 to record the demo video')
test.setTimeout(600_000)

const PASSWORD = process.env.DEX_DEV_PASSWORD ?? 'aegis-dev-only'
const PAUSE = Number(process.env.AEGIS_DEMO_PAUSE ?? 2600)

async function caption(page: Page, text: string, wait = PAUSE) {
  await page.evaluate((t) => {
    let el = document.getElementById('demo-caption')
    if (!el) {
      el = document.createElement('div')
      el.id = 'demo-caption'
      Object.assign(el.style, {
        position: 'fixed', left: '50%', bottom: '28px', transform: 'translateX(-50%)', zIndex: '9999',
        background: 'rgba(8,14,30,0.94)', color: '#fff', border: '1px solid #4f8cff', borderRadius: '10px',
        padding: '14px 22px', font: '500 17px Inter, system-ui, sans-serif', maxWidth: '78%', textAlign: 'center',
        boxShadow: '0 8px 30px rgba(0,0,0,0.5)',
      })
      document.body.appendChild(el)
    }
    el.textContent = t
  }, text)
  await page.waitForTimeout(wait)
}

async function signIn(page: Page, email: string, why: string) {
  await page.goto('/')
  await page.evaluate(() => sessionStorage.clear())
  await page.goto('/')
  await caption(page, why)
  await page.getByRole('button', { name: /sign in with your identity provider/i }).click()
  await page.locator('input[name="login"]').fill(email)
  await page.locator('input[name="password"]').fill(PASSWORD)
  await page.waitForTimeout(600)
  await page.locator('button[type="submit"]').click()
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible({ timeout: 30_000 })
}

test('demo', async ({ browser }) => {
  const ctx = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    recordVideo: { dir: join(process.cwd(), '..', '..', 'demo'), size: { width: 1440, height: 900 } },
  })
  const page = await ctx.newPage()

  await signIn(page, 'alice@aegis.local',
    'Aegis: local-first cloud governance. Alice, an analyst, signs in through OIDC (a local Dex identity provider).')
  await caption(page, 'Overview: failing controls, risk, savings and the tamper-evident audit log, all from Aegis records.', 4000)

  await page.getByRole('link', { name: 'Import & scan' }).click()
  await caption(page, 'Journey 1: scan Terraform before it is applied. Plan in a sandbox, then Trivy, Checkov and the Aegis OPA rules.')
  await page.getByLabel('Terraform fixture').selectOption('insecure-storage')
  await page.getByRole('button', { name: 'Scan', exact: true }).click()
  await expect(page.locator('.scan')).toContainText('succeeded', { timeout: 240_000 })
  await caption(page, 'The scan ran on the durable job queue and finished. Findings map to compliance controls.')

  await page.getByRole('link', { name: 'Risk' }).click()
  await expect(page.locator('.table tbody tr').first()).toBeVisible()
  await caption(page, 'Journey 2: findings ranked by context (exposure, data sensitivity, privilege), not just severity.')
  await page.locator('.table tbody tr').first().click()
  await caption(page, 'Each score explains itself: the reasons and the attack path from the internet.')

  await page.goto('/#/investigate?resource=aws_db_instance.checkout_002')
  await expect(page.getByRole('heading', { name: /Evidence \(\d+ items\)/ })).toBeVisible({ timeout: 20_000 })
  await caption(page, 'An investigation: Aegis reads evidence in a read-only transaction and writes a brief where every sentence cites it.', 3500)
  await page.locator('.claims .cite').nth(3).click()
  await caption(page, 'Citations jump to the evidence. An optional local model may add text, but every claim it makes is validated.')

  await page.getByRole('button', { name: /Propose fix for AEGIS-DB-002/ }).click()
  await page.getByLabel('Rule', { exact: true }).selectOption('AEGIS-DB-002')
  await page.getByLabel('Justification').fill('Checkout database must not be reachable from the internet.')
  await caption(page, 'Journey 5 begins: propose a fix. Aegis simulates it with the same OPA policies before anyone approves.')
  await page.getByRole('button', { name: /Simulate and propose/ }).click()
  await expect(page.getByText(/Approvals \(0 of \d required\)/)).toBeVisible({ timeout: 20_000 })
  await caption(page, 'The simulation shows the rule resolved, nothing new failing, and the resources affected. Production needs two approvers.', 4000)
  const path = new URL(page.url()).hash

  await page.getByRole('link', { name: 'Compliance evidence' }).click()
  await caption(page, 'Journey 3: compliance evidence for NIST CSF 2.0, CIS AWS and an internal baseline.')
  await page.locator('.table tbody tr', { hasText: 'BL-01' }).click()
  await expect(page.getByRole('heading', { name: 'Evidence: BL-01' })).toBeVisible()
  await caption(page, 'Every result points to the exact snapshot version evaluated. Exceptions expire and need a second person.')

  await page.getByRole('link', { name: 'Cost' }).click()
  await expect(page.locator('.bar-row').first()).toBeVisible()
  await caption(page, 'Journey 4: cost by team, anomalies and a forecast from the benchmarked model, plus savings recommendations.', 3500)

  await signIn(page, 'bob@aegis.local', 'Bob, an approver, reviews the proposed change. Alice cannot approve her own request.')
  await page.goto('/' + path)
  await page.getByLabel('Comment').fill('Simulation reviewed; readers are inside the VPC.')
  await caption(page, 'Approvals are bound to this exact plan. If the resource changes, the plan goes stale.')
  await page.getByRole('button', { name: 'Approve' }).click()
  await page.waitForTimeout(1200)

  await signIn(page, 'carol@aegis.local', 'Carol gives the second approval required for a production resource.')
  await page.goto('/' + path)
  await page.getByRole('button', { name: 'Approve' }).click()
  await expect(page.getByRole('button', { name: 'Release change set' })).toBeVisible()
  await page.getByRole('button', { name: 'Release change set' }).click()
  await expect(page.getByRole('heading', { name: 'Change set' })).toBeVisible()
  await page.mouse.wheel(0, 600)
  await caption(page, 'Released as a change set for the normal Terraform pipeline. Aegis never changes the cloud itself; the next import verifies it.', 5000)
  await caption(page, 'Aegis: deterministic first, every action audited, every result reproducible.', 3500)
  await ctx.close()
})
