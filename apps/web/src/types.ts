// Response shapes used by the dashboard (subset of the API).

export interface Resource {
  id: string
  resource_id: string
  resource_type: string
  native_type: string
  region: string
  environment: string
  owner: string
  tags: Record<string, string>
  configuration: Record<string, unknown>
  current_version: number
  updated_at: string
  deleted_at?: string
}

export interface ImportReport {
  import_id: string
  duplicate: boolean
  resource_count: number
  created: number
  updated: number
  deleted: number
  unchanged: number
  warnings: { resource_id: string; code: string; detail: string }[]
}

export interface Scan {
  id: string
  source_ref: string
  status: string
  attempts: number
  last_error?: string
  plan_summary?: Record<string, number>
  created_at: string
  finished_at?: string
  [k: string]: unknown
}

export interface Assessment {
  rule_id: string
  subject: string
  resource_type: string
  rule_severity: string
  score: number
  band: string
  reasons: string[]
  blast_radius: string[]
  attack_path?: { from: string; to: string; via: string; reason: string }[]
  contributions: Record<string, number>
}

export interface RiskRun {
  id: string
  created_at: string
  summary: { findings: number; by_band: Record<string, number>; internet_reachable_sensitive_targets: number }
  assessments: Assessment[]
}

export interface AttackPath {
  target: string
  target_type: string
  sensitivity: number
  hops: { from: string; to: string; via: string; reason: string }[]
}

export interface Claim {
  text: string
  citations: string[]
}

export interface Evidence {
  id: string
  kind: string
  source: string
  summary: string
  facts: Record<string, unknown>
}

export interface Investigation {
  id: string
  resource_id: string
  question: string
  actor: string
  created_at: string
  evidence_sha256: string
  evidence: Evidence[]
  brief: { claims: Claim[]; next_steps: Claim[] }
  model: { status: string; model?: string; accepted: Claim[]; rejected: { claim: Claim; reasons: string[] }[]; error?: string }
  notice: string
}

export interface Framework {
  id: string
  name: string
  version: string
  official: boolean
}

export interface RuleStatus {
  rule_id: string
  title: string
  severity: string
  coverage: string
  review_status: string
  pass: number
  fail: number
  excepted: number
}

export interface ControlStatus {
  control_id: string
  title: string
  status: string
  stale: boolean
  last_evaluated_at?: string
  pass: number
  fail: number
  excepted: number
  rules: RuleStatus[]
}

export interface Coverage {
  notice: string
  summary: Record<string, number>
  controls: ControlStatus[]
}

export interface ControlDetail extends ControlStatus {
  evaluations: { rule_id: string; subject: string; result: string; message: string; evaluated_at: string; evidence: Record<string, unknown> }[]
  exceptions: ExceptionView[]
  remediation?: string[] | string
}

export interface ExceptionView {
  id: string
  rule_id: string
  subject: string
  justification: string
  status: string
  requested_by: string
  decided_by?: string
  expires_at: string
}

export interface CostSummary {
  from: string
  to: string
  total_usd: number
  groups: { key: string; usd: number; share: number }[]
}

export interface MLResult {
  model: string
  data_from: string
  data_to: string
  created_at: string
  points: Record<string, number | string>[]
}

export interface Recommendation {
  id: string
  kind: string
  resource_id: string
  team: string
  as_of: string
  details: Record<string, unknown>
  projected_monthly_savings: number
  status: string
  measured_monthly_savings?: number
  measurement_note?: string
}

export interface Change {
  path: string
  before: unknown
  after: unknown
}

export interface Remediation {
  id: string
  source: string
  rule_id?: string
  resource_id: string
  account_id: string
  operations: { op: string; path: string; value?: unknown }[]
  justification: string
  requested_by: string
  status: string
  stale_reason?: string
  resource_version: number
  observed_version?: number
  observed_updated_at?: string
  required_approvals: number
  disruptive: boolean
  simulation: {
    failing_before: string[]
    failing_after: string[]
    resolved: string[]
    introduced: string[]
    target_rule?: string
    target_resolved: boolean
    passed: boolean
    blocked_reasons: string[]
    diff: Change[]
    impact: { incoming: string[]; outgoing: string[] }
    notes: string[]
    environment: string
  }
  plan_sha256: string
  created_at: string
  approvals: { actor: string; decision: string; comment: string; created_at: string }[]
  change_set?: { instructions: string; native_type: string; operations: unknown[]; signed?: { key_id: string; signature: string; payload: unknown } }
  verification?: { verified: boolean; config_matches: boolean; target_resolved: boolean; mismatched_paths: string[]; unexpected_failures: string[] }
}

export interface Template {
  rule_id: string
  title: string
  disruptive: boolean
  note: string
}

export interface Binding {
  subject: string
  role: string
  granted_by: string
  created_at: string
}

export interface Me {
  subject: string
  name?: string
  method: string
  tenant?: string
  roles?: string[]
}

export interface AuditEvent {
  seq: number
  occurred_at: string
  actor: string
  action: string
  target_type: string
  target_id: string
  outcome: string
}

export interface Paged<T> {
  items: T[]
  next_cursor?: string
}

export interface ScanFinding {
  source: string
  rule_id: string
  severity: string
  decision: string
  resource_address: string
  file_path?: string
  start_line?: number
  end_line?: number
  title: string
  fingerprint: string
}

export interface ScanReport extends Scan {
  planned_changes: { address: string; resource_type: string; action: string; destructive: boolean; region?: string }[]
  findings: ScanFinding[]
  counts: Record<string, Record<string, number>>
  blocking: number
}

export interface DriftBaseline {
  id: string
  account_id: string
  import_id: string
  status: string
  approved_by: string
  note: string
  resource_count: number
  created_at: string
}

export interface DriftItem {
  resource_id: string
  resource_type: string
  category: string
  severity: string
  changes?: { path: string; category: string; before: unknown; after: unknown }[]
  new_failures?: string[]
  resolved?: string[]
}

export interface DriftReport {
  id: string
  account_id: string
  baseline_id: string
  actor: string
  counts: { total?: number; by_category?: Record<string, number>; by_severity?: Record<string, number> }
  created_at: string
  items: DriftItem[]
}

export interface Membership {
  slug: string
  name: string
  roles: string[]
}

export interface TypeCount {
  resource_type: string
  count: number
}

export interface Account {
  id: string
  provider: string
  external_id: string
  name: string
  resource_count: number
}
