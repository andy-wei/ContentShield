/** 后端 API 类型定义（与 backend/app/schemas 对应）。 */

export type Decision = 'pass' | 'warn' | 'block'
export type LayerDecision = 'pass' | 'warn' | 'block' | 'skipped'

export interface LayerResult {
  name: 'lexicon' | 'prompt_guard' | 'llama_guard' | 'dlp' | 'indirect_injection' | 'cross_verify'
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
