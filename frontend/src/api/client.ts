/** Axios 客户端 + 各 API 封装。 */
import axios from 'axios'
import type {
  AuditList,
  CategoryCount,
  CategoryRule,
  DlpRule,
  HealthStatus,
  LayerCount,
  LexiconEntry,
  ModerationRequest,
  ModerationResponse,
  NhiPrincipal,
  NhiPrincipalCreated,
  StatsOverview,
  TrendPoint,
} from './types'

const API_BASE = import.meta.env.VITE_API_BASE || ''

const http = axios.create({
  baseURL: API_BASE,
  timeout: 120000,
})

// 拦截器：自动注入 NHI token（从 localStorage 读，避免循环依赖 store）
http.interceptors.request.use((config) => {
  const token = localStorage.getItem('cs_auth_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export const api = {
  // ---- 检测 ----
  // UI 检测台用 /api/moderate（无需 NHI 鉴权）；外部 API 调用用 /v1/moderate
  moderate: async (req: ModerationRequest): Promise<ModerationResponse> => {
    const { data } = await http.post<ModerationResponse>('/api/moderate', req)
    return data
  },

  health: async (): Promise<HealthStatus> => {
    const { data } = await http.get<HealthStatus>('/healthz')
    return data
  },

  // ---- 统计 ----
  statsOverview: async (days = 30): Promise<StatsOverview> => {
    const { data } = await http.get<StatsOverview>('/api/stats/overview', {
      params: { days },
    })
    return data
  },
  statsTrend: async (days = 7): Promise<TrendPoint[]> => {
    const { data } = await http.get<TrendPoint[]>('/api/stats/trend', {
      params: { days },
    })
    return data
  },
  statsCategories: async (days = 30): Promise<CategoryCount[]> => {
    const { data } = await http.get<CategoryCount[]>('/api/stats/categories', {
      params: { days },
    })
    return data
  },
  statsLayers: async (days = 30): Promise<LayerCount[]> => {
    const { data } = await http.get<LayerCount[]>('/api/stats/layers', {
      params: { days },
    })
    return data
  },

  // ---- 规则 ----
  listCategories: async (): Promise<CategoryRule[]> => {
    const { data } = await http.get<CategoryRule[]>('/api/rules/categories')
    return data
  },
  updateCategory: async (
    code: string,
    update: Partial<Pick<CategoryRule, 'enabled' | 'action' | 'description'>>,
  ): Promise<CategoryRule> => {
    const { data } = await http.patch<CategoryRule>(
      `/api/rules/categories/${code}`,
      update,
    )
    return data
  },
  listLexicon: async (category?: string): Promise<LexiconEntry[]> => {
    const { data } = await http.get<LexiconEntry[]>('/api/rules/lexicon', {
      params: { category },
    })
    return data
  },
  addLexicon: async (entry: {
    term: string
    category: string
    lang: 'zh' | 'en'
    action: 'block' | 'warn'
  }): Promise<LexiconEntry> => {
    const { data } = await http.post<LexiconEntry>('/api/rules/lexicon', entry)
    return data
  },
  deleteLexicon: async (id: number): Promise<void> => {
    await http.delete(`/api/rules/lexicon/${id}`)
  },
  listDlp: async (): Promise<DlpRule[]> => {
    const { data } = await http.get<DlpRule[]>('/api/rules/dlp')
    return data
  },
  addDlp: async (rule: {
    name: string
    pattern: string
    category: string
    action: 'block' | 'warn'
    weight: number
  }): Promise<DlpRule> => {
    const { data } = await http.post<DlpRule>('/api/rules/dlp', rule)
    return data
  },
  deleteDlp: async (id: number): Promise<void> => {
    await http.delete(`/api/rules/dlp/${id}`)
  },

  // ---- 审计 ----
  listAudit: async (params: {
    page?: number
    page_size?: number
    decision?: string
    source?: string
    days?: number
  }): Promise<AuditList> => {
    const { data } = await http.get<AuditList>('/api/audit', { params })
    return data
  },
  getAudit: async (id: number) => {
    const { data } = await http.get(`/api/audit/${id}`)
    return data
  },
  auditCsvUrl: (days = 30) => `${API_BASE}/api/audit/export/csv?days=${days}`,

  // ---- NHI 身份管理 ----
  listPrincipals: async (): Promise<NhiPrincipal[]> => {
    const { data } = await http.get<NhiPrincipal[]>('/api/nhi/principals')
    return data
  },
  createPrincipal: async (req: {
    label: string
    principal_type?: string
    scopes?: string
    upstream_provider?: string
    upstream_api_key?: string
    upstream_base_url?: string
  }): Promise<NhiPrincipalCreated> => {
    const { data } = await http.post<NhiPrincipalCreated>('/api/nhi/principals', req)
    return data
  },
  deletePrincipal: async (id: number): Promise<void> => {
    await http.delete(`/api/nhi/principals/${id}`)
  },
  rotateSecret: async (id: number): Promise<{ id: number; client_id: string; client_secret: string }> => {
    const { data } = await http.post(`/api/nhi/principals/${id}/rotate-secret`)
    return data
  },
  listTokens: async (): Promise<unknown[]> => {
    const { data } = await http.get('/api/nhi/tokens')
    return data
  },
  revokeToken: async (jti: string): Promise<{ revoked: boolean }> => {
    const { data } = await http.post(`/api/nhi/tokens/${jti}/revoke`)
    return data
  },

  // ---- OAuth ----
  getToken: async (clientId: string, clientSecret: string): Promise<{
    access_token: string
    expires_in: number
    scope: string
    refresh_token: string
  }> => {
    const { data } = await http.post('/oauth/token', {
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: clientSecret,
    })
    return data
  },

  // ---- 系统配置（交叉验证等 UI 可改配置）----
  getCrossVerifyConfig: async (): Promise<{
    enabled: boolean
    base_url: string
    api_key_masked: string
    api_key_set: boolean
    model: string
  }> => {
    const { data } = await http.get('/api/config/cross-verify')
    return data
  },
  updateCrossVerifyConfig: async (req: {
    enabled: boolean
    base_url: string
    api_key: string
    model: string
  }) => {
    const { data } = await http.put('/api/config/cross-verify', req)
    return data
  },
  testCrossVerify: async (req: {
    enabled: boolean
    base_url: string
    api_key: string
    model: string
  }): Promise<{ success: boolean; latency_ms: number; detail: string }> => {
    const { data } = await http.post('/api/config/cross-verify/test', req)
    return data
  },
}
