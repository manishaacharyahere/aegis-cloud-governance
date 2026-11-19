-- Who imported an inventory snapshot and who requested an IaC scan (both
-- are also audited from now on). Existing rows predate the column.
ALTER TABLE inventory_imports ADD COLUMN imported_by text;
ALTER TABLE iac_scans ADD COLUMN requested_by text;

-- Control history walks a tenant's runs newest first.
CREATE INDEX compliance_runs_tenant_time_idx ON compliance_runs (tenant_id, evaluated_at DESC);

-- Retention and the foreign key check probe risk runs by compliance run.
CREATE INDEX risk_runs_compliance_run_idx ON risk_runs (compliance_run_id);
