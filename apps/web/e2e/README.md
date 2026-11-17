# End-to-end journeys

`journeys.spec.ts` runs the five user journeys in Chromium. It uses the real
API in OIDC mode, real Dex sign-in and the IaC worker, so nothing is mocked:

1. import and scan: upload an inventory snapshot, then run a sandboxed Terraform scan to completion;
2. investigate risk and propose a fix: open the risk ranking and an investigation, follow a citation to
   its evidence, then propose a remediation that is simulated and pending approval;
3. compliance evidence: open a control and see its failing evaluations and snapshot pointers;
4. cost investigation: spend by team, anomalies, forecast and recommendations;
5. controlled remediation:
   - the requester cannot approve their own change;
   - two approvers approve a production change;
   - the change set is released;
   - verification refuses to guess before the next import.

6. drift: an approver approves the e2e account's baseline, then an analyst checks it and sees no drift.

A last test checks that a viewer sees data but no action buttons.

```bash
# stack: core + auth profiles with OIDC and a bootstrap admin
AEGIS_AUTH_MODE=oidc AEGIS_BOOTSTRAP_ADMINS=admin@aegis.local docker compose --profile core --profile auth up -d
# demo roles (once), using an admin token
TOKEN=$(scripts/dev-token.sh admin@aegis.local)
for b in alice@aegis.local:analyst bob@aegis.local:approver carol@aegis.local:approver viewer@aegis.local:viewer; do
  curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "X-Aegis-Tenant: demo" \
    -d "{\"subject\":\"${b%%:*}\",\"role\":\"${b##*:}\"}" http://127.0.0.1:8080/api/v1/access/bindings
done
# IaC worker on the host, the dashboard, then the journeys
go run ./cmd/aegis-worker &
cd apps/web && npm run dev &
npx playwright install chromium
npx playwright test                      # AEGIS_SCREENSHOTS=1 writes ../../screenshots/*.png
```

The demo identities and their password exist only in `infrastructure/auth/dex.yml`, for development.

## Demo video

`demo.spec.ts` records one continuous, captioned session through the same journeys:

```bash
AEGIS_DEMO=1 npx playwright test e2e/demo.spec.ts   # writes ../../demo/*.webm (git-ignored; published as a release asset)
```

The journeys can be run again against the same stack. Journey 2 first closes any open remediation
an earlier run left for its resource (rejecting it if pending, releasing it if approved). Journey 5
uses the remediation journey 2 creates, so run the two together.
