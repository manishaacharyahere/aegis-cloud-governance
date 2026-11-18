-- The tenant policy configuration a remediation was simulated under.
-- Approving or releasing it after the configuration changed marks it stale.
-- NULL for remediations proposed before this column existed (not checked).
ALTER TABLE remediations ADD COLUMN policy_config_sha256 text CHECK (policy_config_sha256 ~ '^[0-9a-f]{64}$');
