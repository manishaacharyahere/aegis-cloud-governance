-- The pull request a released change set was delivered as (GitHub), if any.
ALTER TABLE remediations ADD COLUMN pull_request_url text;
