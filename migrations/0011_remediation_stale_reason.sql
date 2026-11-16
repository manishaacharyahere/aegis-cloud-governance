-- Why a remediation became stale: the resource changed, or the policies
-- changed after the plan was simulated.
ALTER TABLE remediations ADD COLUMN stale_reason text NOT NULL DEFAULT '';
