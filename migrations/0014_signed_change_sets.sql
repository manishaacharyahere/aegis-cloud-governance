-- Released change sets are signed (Ed25519) so a deployment pipeline can
-- verify that a change was approved in Aegis. Stored as text, not jsonb:
-- jsonb would re-format the payload and break the signature over its bytes.
ALTER TABLE remediations ADD COLUMN change_set_signed text;
