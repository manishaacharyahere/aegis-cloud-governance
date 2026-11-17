-- Newest-first report listing per tenant (GET /api/v1/drift/reports).
CREATE INDEX drift_reports_tenant_idx ON drift_reports (tenant_id, created_at DESC, id DESC);
