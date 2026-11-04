/** 后端 API 类型定义（与 backend/app/schemas 对应）。 */

export type Decision = 'pass' | 'warn' | 'block'
export type LayerDecision = 'pass' | 'warn' | 'block' | 'skipped'

export interface LayerResult {
  name: 'lexicon' | 'prompt_guard' | 'llama_guard' | 'dlp' | 'indirect_injection' | 'cross_verify' | 'code_shield'
  hit: boolean
  decision: LayerDecision
  details: Record<string, unknown>
  latency_ms: number
}

export interface ModerationResponse {
  decision: Decision
  risk_score: number
  layers: Record<string, LayerResult>
  categories: string[]
  explanations: string[]
  latency_ms: number
}

export interface ModerationRequest {
  text: string
  source?: 'user_prompt' | 'llm_response' | 'gateway' | 'test'
  skip_audit?: boolean
}

export interface CategoryRule {
  id: number
  code: string
  name: string
  enabled: boolean
  action: 'block' | 'warn' | 'off'
  description: string
  layer: string
  order: number
  updated_at: string
}

export interface LexiconEntry {
  id: number
  term: string
  category: string
  lang: string
  action: string
  enabled: boolean
  created_at: string
}

export interface DlpRule {
  id: number
  name: string
  pattern: string
  category: string
  action: string
  weight: number
  enabled: boolean
  created_at: string
}

export interface AuditItem {
  id: number
  created_at: string
  source: string
  input_text: string
  input_length: number
  decision: Decision
  risk_score: number
  categories: string[]
  explanations: string[]
  latency_ms: number
}

export interface AuditList {
  total: number
  page: number
  page_size: number
  items: AuditItem[]
}

export interface StatsOverview {
  days: number
  total: number
  blocked: number
  warned: number
  passed: number
  block_rate: number
  avg_latency_ms: number
  avg_risk_score: number
}

export interface TrendPoint {
  date: string
  total: number
  blocked: number
  warned: number
}

export interface CategoryCount {
  category: string
  count: number
}

export interface LayerCount {
  layer: string
  count: number
}

export interface HealthStatus {
  status: string
  inference_profile?: string
  backends?: Record<string, Record<string, unknown>>
}

// ---- NHI 身份与凭据管理 ----

export interface NhiPrincipal {
  id: number
  client_id: string
  label: string
  principal_type: string
  enabled: boolean
  scopes: string
  upstream_provider: string
  upstream_base_url: string
  created_at: string
  updated_at: string
  last_used_at: string | null
}

export interface NhiPrincipalCreated extends NhiPrincipal {
  client_secret: string // 仅创建时返回明文
}

export interface AccessTokenInfo {
  id: number
  jti: string
  principal_id: number
  subject: string
  scopes: string
  expires_at: string
  revoked: boolean
  created_at: string
}

// ---- 威胁建模 ----

export type ThreatCategory =
  | 'S'
  | 'T'
  | 'R'
  | 'I'
  | 'D'
  | 'E'
  | 'prompt_injection'
  | 'data_poisoning'
  | 'model_inversion'
  | 'alignment_bypass'
  | 'loss_of_provenance'

export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical'
export type ThreatStatus = 'open' | 'mitigating' | 'mitigated' | 'accepted'
export type AssetType =
  | 'external_entity'
  | 'process'
  | 'data_store'
  | 'data_flow'
  | 'trust_boundary'

export interface ThreatProject {
  id: number
  name: string
  description: string
  status: 'draft' | 'active' | 'archived'
  created_at: string
  updated_at: string
}

export interface ThreatProjectWithStats extends ThreatProject {
  asset_count: number
  threat_count: number
  open_count: number
  critical_count: number
}

export interface Asset {
  id: number
  project_id: number
  name: string
  description: string
  asset_type: AssetType
  tech_stack: string[]
  properties: Record<string, unknown>
  created_at: string
}

export interface Threat {
  id: number
  project_id: number
  asset_id: number | null
  title: string
  description: string
  category: ThreatCategory
  likelihood: number
  impact: number
  risk_level: RiskLevel
  mitigation: string
  status: ThreatStatus
  source: 'llm_generated' | 'manual'
  created_at: string
  updated_at: string
}

export interface MitigationControl {
  id: number
  threat_id: number
  control_type: 'detection_rule' | 'audit_evidence' | 'agent_policy' | 'manual'
  ref_layer:
    | 'lexicon'
    | 'prompt_guard'
    | 'llama_guard'
    | 'dlp'
    | 'indirect_injection'
    | 'cross_verify'
    | 'code_shield'
    | 'alignment_check'
    | 'tool_whitelist'
    | 'rate_limiter'
    | 'manual'
  ref_id: string
  description: string
  effectiveness: 'planned' | 'in_effect' | 'verified' | 'failed'
  created_at: string
}

export interface ControlEvidence {
  control_id: number
  ref_layer: string
  effectiveness: string
  blocked_count_30d: number
  warned_count_30d: number
  total_count_30d: number
  last_triggered: string | null
  note: string
}

export interface ThreatEvidence {
  threat_id: number
  controls: ControlEvidence[]
}

export interface GenerateResult {
  success: boolean
  generated: number
  threats: Threat[]
  detail: string
}

// ==================== DevSecOps 扫描平台 ====================

export type TargetType = 'git' | 'path' | 'image'
export type JobStatus = 'pending' | 'running' | 'completed' | 'failed' | 'canceled'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type FindingCategory = 'sast' | 'sca' | 'secret' | 'container' | 'config' | 'license'

export interface ScanTarget {
  id: number
  name: string
  target_type: TargetType
  location: string
  ref: string
  last_commit: string
  created_at: string
  updated_at: string
}

export interface ScanJobSummary {
  id: number
  target_id: number
  target_name: string
  trigger: 'manual' | 'ci' | 'schedule'
  tools: string[]
  status: JobStatus
  progress: number
  commit: string
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  started_at: string | null
  finished_at: string | null
  created_at: string
}

export interface ScanJob extends ScanJobSummary {
  celery_task_id: string
  workdir?: string
  error: string
}

export interface Finding {
  id: number
  job_id: number
  tool: string
  severity: Severity
  category: FindingCategory
  rule_id: string
  cve: string
  title: string
  message: string
  file: string
  line: number
  fix: string
  fingerprint: string
  created_at: string
}

export interface FindingList {
  items: Finding[]
  total: number
  counts: Record<string, number>
}

export interface ScanPolicy {
  id: number
  name: string
  description: string
  max_critical: number
  max_high: number
  max_medium: number
  max_low: number
  max_info: number
  is_default: boolean
  created_at: string
  updated_at: string
}

export interface GateResult {
  passed: boolean
  policy_name: string
  counts: Record<string, number>
  reasons: string[]
}

export interface ToolInfo {
  name: string
  category: FindingCategory
  description: string
  available: boolean
}

// ==================== 训练数据安全扫描 ====================

export type DatasetFormat = 'jsonl' | 'csv' | 'txt'
export type TrainingScanStatus = 'pending' | 'running' | 'completed' | 'failed'

export interface Dataset {
  id: number
  name: string
  description: string
  format: DatasetFormat
  source: string
  version: string
  record_count: number
  file_path: string
  created_at: string
  updated_at: string
}

export interface DatasetScanSummary {
  id: number
  dataset_id: number
  dataset_name: string
  status: TrainingScanStatus
  scanned_count: number
  flagged_count: number
  stats: Record<string, number>
  progress: number
  started_at: string | null
  finished_at: string | null
  created_at: string
}

export interface DatasetScan extends DatasetScanSummary {
  error: string
}

export interface DatasetFinding {
  id: number
  scan_id: number
  record_idx: number
  record_hash: string
  issue_types: string[]
  decision: string
  risk_score: number
  layers: Record<string, { hit: boolean; decision: string }>
  categories: string[]
  poison_type: string
  preview: string
  created_at: string
}

export interface DatasetFindingList {
  items: DatasetFinding[]
  total: number
  issue_counts: Record<string, number>
}

export interface DatasetScanReport {
  scan: DatasetScan
  dataset: Dataset
  issue_distribution: Record<string, number>
  poison_suspect_count: number
  risk_distribution: Record<string, number>
  top_findings: DatasetFinding[]
}

// ==================== LLM 红队对抗测试 ====================

export type CampaignStatus = 'pending' | 'running' | 'completed' | 'failed'
export type AttackSource = 'preset' | 'template' | 'llm'
export type AttackCategory =
  | 'jailbreak'
  | 'prompt_injection'
  | 'harmful_request'
  | 'encoding'
  | 'social_engineering'

export interface TargetConfig {
  base_url: string
  api_key: string
  model: string
  temperature: number
  max_tokens: number
}

export interface AttackStrategy {
  source: 'preset' | 'template' | 'llm' | 'mixed'
  count: number
  categories: AttackCategory[]
  llm_base_url?: string
  llm_api_key?: string
  llm_model?: string
}

export interface Campaign {
  id: number
  name: string
  description: string
  target_config: TargetConfig
  strategy: AttackStrategy
  status: CampaignStatus
  total_attacks: number
  success_count: number
  asr: number
  progress: number
  error: string
  celery_task_id: string
  started_at: string | null
  finished_at: string | null
  created_at: string
}

export interface AttackCase {
  id: number
  campaign_id: number
  prompt: string
  source: AttackSource
  category: AttackCategory
  template_name: string
  created_at: string
}

export interface AttackResult {
  id: number
  case_id: number
  campaign_id: number
  response: string
  judged_unsafe: boolean
  judged_category: string
  judge_raw: string
  latency_ms: number
  success: boolean
  error: string
  created_at: string
  case?: AttackCase
}

export interface AttackResultList {
  items: AttackResult[]
  total: number
  category_stats: Record<string, { total: number; success: number; asr: number }>
}

export interface CampaignReport {
  campaign: Campaign
  overall_asr: number
  category_breakdown: Record<string, { total: number; success: number; asr: number }>
  top_successful_attacks: AttackResult[]
  risk_insights: string[]
}

// ==================== 模型供应链安全（MBOM）====================

export type ModelType = 'base' | 'fine_tuned' | 'lora_adapter' | 'embedding' | 'guard'
export type ArtifactSource =
  | 'huggingface'
  | 'internal'
  | 'openai'
  | 'anthropic'
  | 'custom'
export type SignatureStatus = 'unsigned' | 'signed' | 'verified' | 'failed'
export type IntegrityStatus = 'unknown' | 'verified' | 'tampered'

export interface ModelArtifact {
  id: number
  name: string
  model_type: ModelType
  source: ArtifactSource
  source_id: string
  version: string
  file_path: string
  size_bytes: number
  sha256: string
  license: string
  signature_status: SignatureStatus
  integrity_status: IntegrityStatus
  model_card: Record<string, unknown>
  security_assessment: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface ModelArtifactSummary {
  id: number
  name: string
  model_type: ModelType
  source: ArtifactSource
  source_id: string
  version: string
  size_bytes: number
  sha256: string
  license: string
  signature_status: SignatureStatus
  integrity_status: IntegrityStatus
  depends_on_count: number
  dependents_count: number
  created_at: string
}

export interface IntegrityCheckResult {
  artifact_id: number
  verified: boolean
  expected_sha256: string
  actual_sha256: string
  message: string
}

export interface ModelDependency {
  id: number
  artifact_id: number
  depends_on_id: number
  dependency_type: string
  created_at: string
}

export interface RiskAssessment {
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  risk_score: number
  issues: string[]
  recommendations: string[]
}

export interface MBOMExport {
  artifacts: ModelArtifact[]
  dependencies: ModelDependency[]
  risk_summary: Record<string, number>
}

// ==================== 成员推理攻击（MIA）====================

export interface MIAResult {
  campaign_id: number
  name: string
  status: CampaignStatus
  mi_advantage: number
  certainty_gap: number
  member_avg_certainty: number
  nonmember_avg_certainty: number
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  interpretation: string
  per_probe: Array<{
    text: string
    is_member: boolean
    response_length: number
    certainty: number
    latency_ms: number
  }>
  created_at: string | null
}

// ==================== OWASP LLM Top 10 审计 checklist ====================

export type ChecklistStatus = 'pending' | 'pass' | 'fail' | 'na'

export interface AuditChecklistItem {
  id: number
  owasp_id: string
  name: string
  threat_category: string
  audit_points: string[]
  check_method: string
  ref_layer: string
  status: ChecklistStatus
  evidence: string
  auditor: string
  created_at: string
  updated_at: string
}

export interface ChecklistSummary {
  total: number
  pass_count: number
  fail_count: number
  pending_count: number
  na_count: number
  pass_rate: number
}
