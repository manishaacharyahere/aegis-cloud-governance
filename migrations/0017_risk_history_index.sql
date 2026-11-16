-- Risk assessment looks up each failing finding's history across compliance
-- runs by (rule, subject). With only (tenant_id, rule_id) indexed, every
-- lookup scanned all evaluations of the rule; the scale test showed risk
-- assessment growing faster than linearly because of it.
CREATE INDEX compliance_evaluations_subject_idx ON compliance_evaluations (tenant_id, rule_id, subject);
