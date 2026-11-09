/** Axios 客户端 + 各 API 封装。 */
import axios from 'axios'
import type {
  Asset,
  AuditChecklistItem,
  AttackResultList,
  AuditList,
  Campaign,
  CampaignReport,
  CategoryCount,
  CategoryRule,
  ChecklistSummary,
  Dataset,
  DatasetFindingList,
  DatasetScan,
  DatasetScanReport,
  DatasetScanSummary,
  DlpRule,
  FindingList,
  GateResult,
  GenerateResult,
  HealthStatus,
  IntegrityCheckResult,
  LayerCount,
  LexiconEntry,
  MBOMExport,
  MIAResult,
  MitigationControl,
  ModelArtifact,
  ModelArtifactSummary,
  ModerationRequest,
  ModerationResponse,
  NhiPrincipal,
  NhiPrincipalCreated,
  RiskAssessment,
  ScanJob,
  ScanJobSummary,
  ScanPolicy,
  ScanTarget,
  StatsOverview,
  Threat,
  ThreatEvidence,
  ThreatProject,
  ThreatProjectWithStats,
  ToolInfo,
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

  // ---- 安全策略配置 ----
  getSecurityConfig: async (): Promise<{
    oauth_max_attempts: number
    oauth_lockout_minutes: number
    rate_limit_oauth: number
    rate_limit_api: number
    rate_limit_admin: number
    admin_token_required: boolean
  }> => {
    const { data } = await http.get('/api/config/security')
    return data
  },
  updateSecurityConfig: async (req: {
    oauth_max_attempts: number
    oauth_lockout_minutes: number
    rate_limit_oauth: number
    rate_limit_api: number
    rate_limit_admin: number
    admin_token_required: boolean
  }) => {
    const { data } = await http.put('/api/config/security', req)
    return data
  },

  // ---- 代码安全（L5 CodeShield）配置 ----
  getCodeShieldConfig: async (): Promise<{
    enabled: boolean
    action: 'warn' | 'block'
  }> => {
    const { data } = await http.get('/api/config/code-shield')
    return data
  },
  updateCodeShieldConfig: async (req: {
    enabled: boolean
    action: 'warn' | 'block'
  }) => {
    const { data } = await http.put('/api/config/code-shield', req)
    return data
  },

  // ---- Agent 动作审计（第 3 层应用安全）----
  getAgentActions: async (params?: {
    blocked?: boolean
    subject?: string
    page?: number
    page_size?: number
  }): Promise<{
    total: number
    page: number
    page_size: number
    items: Array<{
      id: number
      created_at: string
      principal_id: number | null
      subject: string
      tool_name: string
      arguments_summary: string
      source: string
      blocked: boolean
      block_reason: string
      request_id: string
    }>
  }> => {
    const { data } = await http.get('/api/audit/agent-actions', { params })
    return data
  },

  // ---- NHI 工具白名单 ----
  getPrincipalTools: async (id: number): Promise<{ allowed_tools: string[] }> => {
    const { data } = await http.get(`/api/nhi/principals/${id}/tools`)
    return data
  },
  updatePrincipalTools: async (id: number, tools: string[]): Promise<{ allowed_tools: string[] }> => {
    const { data } = await http.put(`/api/nhi/principals/${id}/tools`, { allowed_tools: tools })
    return data
  },

  // ---- 危险工具黑名单 ----
  getDangerousTools: async (): Promise<{ builtin: string[]; custom: string[] }> => {
    const { data } = await http.get('/api/config/dangerous-tools')
    return data
  },
  updateDangerousTools: async (custom: string[]): Promise<{ custom: string[] }> => {
    const { data } = await http.put('/api/config/dangerous-tools', { custom })
    return data
  },

  // ---- 行为对齐（AlignmentCheck）配置 ----
  getAlignmentCheckConfig: async (): Promise<{
    enabled: boolean
    action: 'warn' | 'block'
    base_url: string
    api_key_masked: string
    api_key_set: boolean
    model: string
    source_hint: string
  }> => {
    const { data } = await http.get('/api/config/alignment-check')
    return data
  },
  updateAlignmentCheckConfig: async (req: {
    enabled: boolean
    action: 'warn' | 'block'
    base_url: string
    api_key: string
    model: string
  }) => {
    const { data } = await http.put('/api/config/alignment-check', req)
    return data
  },

  // ---- 威胁建模 LLM 配置 ----
  getThreatModelConfig: async (): Promise<{
    enabled: boolean
    base_url: string
    api_key_masked: string
    api_key_set: boolean
    model: string
  }> => {
    const { data } = await http.get('/api/config/threat-model')
    return data
  },
  updateThreatModelConfig: async (req: {
    enabled: boolean
    base_url: string
    api_key: string
    model: string
  }) => {
    const { data } = await http.put('/api/config/threat-model', req)
    return data
  },

  // ---- 威胁建模：项目 ----
  listThreatProjects: async (): Promise<ThreatProjectWithStats[]> => {
    const { data } = await http.get<ThreatProjectWithStats[]>('/api/threat-model/projects')
    return data
  },
  createThreatProject: async (req: {
    name: string
    description?: string
    status?: 'draft' | 'active' | 'archived'
  }): Promise<ThreatProject> => {
    const { data } = await http.post<ThreatProject>('/api/threat-model/projects', req)
    return data
  },
  getThreatProject: async (id: number): Promise<ThreatProject> => {
    const { data } = await http.get<ThreatProject>(`/api/threat-model/projects/${id}`)
    return data
  },
  updateThreatProject: async (
    id: number,
    req: Partial<{ name: string; description: string; status: 'draft' | 'active' | 'archived' }>,
  ): Promise<ThreatProject> => {
    const { data } = await http.put<ThreatProject>(`/api/threat-model/projects/${id}`, req)
    return data
  },
  deleteThreatProject: async (id: number): Promise<void> => {
    await http.delete(`/api/threat-model/projects/${id}`)
  },

  // ---- 威胁建模：资产 ----
  listAssets: async (projectId: number): Promise<Asset[]> => {
    const { data } = await http.get<Asset[]>(`/api/threat-model/projects/${projectId}/assets`)
    return data
  },
  createAsset: async (
    projectId: number,
    req: {
      name: string
      description?: string
      asset_type?: string
      tech_stack?: string[]
      properties?: Record<string, unknown>
    },
  ): Promise<Asset> => {
    const { data } = await http.post<Asset>(
      `/api/threat-model/projects/${projectId}/assets`,
      req,
    )
    return data
  },
  updateAsset: async (
    id: number,
    req: Partial<{
      name: string
      description: string
      asset_type: string
      tech_stack: string[]
      properties: Record<string, unknown>
    }>,
  ): Promise<Asset> => {
    const { data } = await http.put<Asset>(`/api/threat-model/assets/${id}`, req)
    return data
  },
  deleteAsset: async (id: number): Promise<void> => {
    await http.delete(`/api/threat-model/assets/${id}`)
  },

  // ---- 威胁建模：威胁 ----
  listThreats: async (
    projectId: number,
    params?: { status?: string; category?: string; risk_level?: string },
  ): Promise<Threat[]> => {
    const { data } = await http.get<Threat[]>(`/api/threat-model/projects/${projectId}/threats`, {
      params,
    })
    return data
  },
  createThreat: async (req: {
    project_id: number
    asset_id?: number | null
    title: string
    description?: string
    category?: string
    likelihood?: number
    impact?: number
    mitigation?: string
    status?: string
  }): Promise<Threat> => {
    const { data } = await http.post<Threat>('/api/threat-model/threats', req)
    return data
  },
  updateThreat: async (
    id: number,
    req: Partial<{
      asset_id: number | null
      title: string
      description: string
      category: string
      likelihood: number
      impact: number
      mitigation: string
      status: string
    }>,
  ): Promise<Threat> => {
    const { data } = await http.put<Threat>(`/api/threat-model/threats/${id}`, req)
    return data
  },
  updateThreatStatus: async (
    id: number,
    status: string,
  ): Promise<Threat> => {
    const { data } = await http.patch<Threat>(`/api/threat-model/threats/${id}/status`, {
      status,
    })
    return data
  },
  deleteThreat: async (id: number): Promise<void> => {
    await http.delete(`/api/threat-model/threats/${id}`)
  },

  // ---- 威胁建模：LLM 生成 ----
  generateThreats: async (
    projectId: number,
    forceRegenerate = false,
  ): Promise<GenerateResult> => {
    const { data } = await http.post<GenerateResult>(
      `/api/threat-model/projects/${projectId}/generate`,
      { force_regenerate: forceRegenerate },
    )
    return data
  },

  // ---- 威胁建模：缓解控制 ----
  listControls: async (threatId: number): Promise<MitigationControl[]> => {
    const { data } = await http.get<MitigationControl[]>(
      `/api/threat-model/threats/${threatId}/controls`,
    )
    return data
  },
  createControl: async (
    threatId: number,
    req: {
      control_type?: string
      ref_layer?: string
      ref_id?: string
      description?: string
      effectiveness?: string
    },
  ): Promise<MitigationControl> => {
    const { data } = await http.post<MitigationControl>(
      `/api/threat-model/threats/${threatId}/controls`,
      req,
    )
    return data
  },
  updateControl: async (
    id: number,
    req: Partial<{
      control_type: string
      ref_layer: string
      ref_id: string
      description: string
      effectiveness: string
    }>,
  ): Promise<MitigationControl> => {
    const { data } = await http.put<MitigationControl>(`/api/threat-model/controls/${id}`, req)
    return data
  },
  deleteControl: async (id: number): Promise<void> => {
    await http.delete(`/api/threat-model/controls/${id}`)
  },

  // ---- 威胁建模：证据（轻量联动）----
  getThreatEvidence: async (threatId: number): Promise<ThreatEvidence> => {
    const { data } = await http.get<ThreatEvidence>(
      `/api/threat-model/threats/${threatId}/evidence`,
    )
    return data
  },

  // ---- DevSecOps 扫描平台 ----
  // 扫描目标
  listScanTargets: async (): Promise<ScanTarget[]> => {
    const { data } = await http.get<ScanTarget[]>('/api/scan/targets')
    return data
  },
  createScanTarget: async (req: {
    name: string
    target_type: 'git' | 'path' | 'image'
    location: string
    ref?: string
  }): Promise<ScanTarget> => {
    const { data } = await http.post<ScanTarget>('/api/scan/targets', req)
    return data
  },
  deleteScanTarget: async (id: number): Promise<void> => {
    await http.delete(`/api/scan/targets/${id}`)
  },

  // 扫描任务
  listScanJobs: async (params?: {
    target_id?: number
    status?: string
    limit?: number
    offset?: number
  }): Promise<ScanJobSummary[]> => {
    const { data } = await http.get<ScanJobSummary[]>('/api/scan/jobs', { params })
    return data
  },
  createScanJob: async (req: {
    target_id: number
    tools: string[]
    trigger?: 'manual' | 'ci' | 'schedule'
  }): Promise<ScanJob> => {
    const { data } = await http.post<ScanJob>('/api/scan/jobs', req)
    return data
  },
  getScanJob: async (id: number): Promise<ScanJob> => {
    const { data } = await http.get<ScanJob>(`/api/scan/jobs/${id}`)
    return data
  },
  cancelScanJob: async (id: number): Promise<void> => {
    await http.post(`/api/scan/jobs/${id}/cancel`)
  },

  // Finding 查询
  listFindings: async (
    jobId: number,
    params?: { severity?: string; tool?: string; category?: string },
  ): Promise<FindingList> => {
    const { data } = await http.get<FindingList>(`/api/scan/jobs/${jobId}/findings`, {
      params,
    })
    return data
  },

  // 门禁策略
  listScanPolicies: async (): Promise<ScanPolicy[]> => {
    const { data } = await http.get<ScanPolicy[]>('/api/scan/policies')
    return data
  },
  createScanPolicy: async (req: {
    name: string
    description?: string
    max_critical?: number
    max_high?: number
    max_medium?: number
    max_low?: number
    max_info?: number
    is_default?: boolean
  }): Promise<ScanPolicy> => {
    const { data } = await http.post<ScanPolicy>('/api/scan/policies', req)
    return data
  },
  updateScanPolicy: async (
    id: number,
    req: {
      name: string
      description?: string
      max_critical?: number
      max_high?: number
      max_medium?: number
      max_low?: number
      max_info?: number
      is_default?: boolean
    },
  ): Promise<ScanPolicy> => {
    const { data } = await http.put<ScanPolicy>(`/api/scan/policies/${id}`, req)
    return data
  },
  deleteScanPolicy: async (id: number): Promise<void> => {
    await http.delete(`/api/scan/policies/${id}`)
  },

  // 门禁判定
  evaluateGate: async (jobId: number, policyId?: number): Promise<GateResult> => {
    const { data } = await http.get<GateResult>(`/api/scan/jobs/${jobId}/gate`, {
      params: policyId ? { policy_id: policyId } : undefined,
    })
    return data
  },

  // 可用工具
  listScanTools: async (): Promise<ToolInfo[]> => {
    const { data } = await http.get<ToolInfo[]>('/api/scan/tools')
    return data
  },

  // ---- 训练数据安全扫描 ----
  // 数据集管理
  listDatasets: async (): Promise<Dataset[]> => {
    const { data } = await http.get<Dataset[]>('/api/training/datasets')
    return data
  },
  uploadDataset: async (req: {
    name: string
    format: 'jsonl' | 'csv' | 'txt'
    source?: string
    version?: string
    description?: string
    file: File
  }): Promise<Dataset> => {
    const form = new FormData()
    form.append('name', req.name)
    form.append('format', req.format)
    form.append('source', req.source || 'internal')
    form.append('version', req.version || '')
    form.append('description', req.description || '')
    form.append('file', req.file)
    const { data } = await http.post<Dataset>('/api/training/datasets', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data
  },
  deleteDataset: async (id: number): Promise<void> => {
    await http.delete(`/api/training/datasets/${id}`)
  },

  // 扫描任务
  listDatasetScans: async (params?: {
    dataset_id?: number
    limit?: number
    offset?: number
  }): Promise<DatasetScanSummary[]> => {
    const { data } = await http.get<DatasetScanSummary[]>('/api/training/scans', { params })
    return data
  },
  createDatasetScan: async (datasetId: number): Promise<DatasetScan> => {
    const { data } = await http.post<DatasetScan>(
      `/api/training/datasets/${datasetId}/scan`,
    )
    return data
  },
  getDatasetScan: async (id: number): Promise<DatasetScan> => {
    const { data } = await http.get<DatasetScan>(`/api/training/scans/${id}`)
    return data
  },

  // 问题样本
  listDatasetFindings: async (
    scanId: number,
    params?: { issue_type?: string; poison_type?: string },
  ): Promise<DatasetFindingList> => {
    const { data } = await http.get<DatasetFindingList>(
      `/api/training/scans/${scanId}/findings`,
      { params },
    )
    return data
  },

  // 扫描报告
  getDatasetScanReport: async (scanId: number): Promise<DatasetScanReport> => {
    const { data } = await http.get<DatasetScanReport>(
      `/api/training/scans/${scanId}/report`,
    )
    return data
  },

  // ---- LLM 红队对抗测试 ----
  listCampaigns: async (): Promise<Campaign[]> => {
    const { data } = await http.get<Campaign[]>('/api/redteam/campaigns')
    return data
  },
  createCampaign: async (req: {
    name: string
    description?: string
    target: {
      base_url: string
      api_key: string
      model: string
      temperature?: number
      max_tokens?: number
    }
    strategy: {
      source: 'preset' | 'template' | 'llm' | 'mixed'
      count: number
      categories?: string[]
      llm_base_url?: string
      llm_api_key?: string
      llm_model?: string
    }
  }): Promise<Campaign> => {
    const { data } = await http.post<Campaign>('/api/redteam/campaigns', req)
    return data
  },
  getCampaign: async (id: number): Promise<Campaign> => {
    const { data } = await http.get<Campaign>(`/api/redteam/campaigns/${id}`)
    return data
  },
  deleteCampaign: async (id: number): Promise<void> => {
    await http.delete(`/api/redteam/campaigns/${id}`)
  },
  listAttackResults: async (
    campaignId: number,
    params?: { success_only?: boolean; category?: string },
  ): Promise<AttackResultList> => {
    const { data } = await http.get<AttackResultList>(
      `/api/redteam/campaigns/${campaignId}/results`,
      { params },
    )
    return data
  },
  getCampaignReport: async (campaignId: number): Promise<CampaignReport> => {
    const { data } = await http.get<CampaignReport>(
      `/api/redteam/campaigns/${campaignId}/report`,
    )
    return data
  },
  /** 导出红队训练数据（dpo 偏好对 / sft 正例）为 JSONL 文件下载。返回导出条数。 */
  exportRedteamTraining: async (
    campaignId: number,
    fmt: 'dpo' | 'sft',
  ): Promise<number> => {
    const resp = await http.get(
      `/api/redteam/campaigns/${campaignId}/export-training`,
      { params: { fmt }, responseType: 'blob' },
    )
    const count = Number(resp.headers?.['x-record-count'] ?? 0)
    const url = URL.createObjectURL(resp.data as Blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `redteam_${fmt}_${campaignId}.jsonl`
    a.click()
    URL.revokeObjectURL(url)
    return count
  },

  // ---- 模型供应链安全（MBOM）----
  listArtifacts: async (params?: {
    model_type?: string
    source?: string
  }): Promise<ModelArtifactSummary[]> => {
    const { data } = await http.get<ModelArtifactSummary[]>('/api/mbom/artifacts', {
      params,
    })
    return data
  },
  createArtifact: async (req: {
    name: string
    model_type?: string
    source?: string
    source_id?: string
    version?: string
    file_path?: string
    license?: string
  }): Promise<ModelArtifact> => {
    const { data } = await http.post<ModelArtifact>('/api/mbom/artifacts', req)
    return data
  },
  getArtifact: async (id: number): Promise<ModelArtifact> => {
    const { data } = await http.get<ModelArtifact>(`/api/mbom/artifacts/${id}`)
    return data
  },
  updateArtifact: async (id: number, updates: Record<string, unknown>): Promise<ModelArtifact> => {
    const { data } = await http.put<ModelArtifact>(`/api/mbom/artifacts/${id}`, updates)
    return data
  },
  deleteArtifact: async (id: number): Promise<void> => {
    await http.delete(`/api/mbom/artifacts/${id}`)
  },
  verifyArtifact: async (id: number): Promise<IntegrityCheckResult> => {
    const { data } = await http.post<IntegrityCheckResult>(
      `/api/mbom/artifacts/${id}/verify`,
    )
    return data
  },
  rehashArtifact: async (id: number): Promise<{ sha256: string }> => {
    const { data } = await http.post<{ sha256: string }>(
      `/api/mbom/artifacts/${id}/rehash`,
    )
    return data
  },
  getArtifactRisk: async (id: number): Promise<RiskAssessment> => {
    const { data } = await http.get<RiskAssessment>(`/api/mbom/artifacts/${id}/risk`)
    return data
  },
  exportMBOM: async (): Promise<MBOMExport> => {
    const { data } = await http.get<MBOMExport>('/api/mbom/export')
    return data
  },

  // ---- 成员推理攻击（MIA）----
  createMIA: async (req: {
    name: string
    description?: string
    target_base_url?: string
    target_api_key: string
    target_model?: string
  }): Promise<{ campaign_id: number; status: string }> => {
    const { data } = await http.post('/api/redteam/membership-inference', req)
    return data
  },
  getMIA: async (campaignId: number): Promise<MIAResult> => {
    const { data } = await http.get<MIAResult>(
      `/api/redteam/membership-inference/${campaignId}`,
    )
    return data
  },

  // ---- OWASP LLM Top 10 审计 checklist ----
  listChecklist: async (status?: string): Promise<AuditChecklistItem[]> => {
    const { data } = await http.get<AuditChecklistItem[]>('/api/audit-checklist', {
      params: status ? { status } : undefined,
    })
    return data
  },
  getChecklistSummary: async (): Promise<ChecklistSummary> => {
    const { data } = await http.get<ChecklistSummary>('/api/audit-checklist/summary')
    return data
  },
  updateChecklistItem: async (
    itemId: number,
    req: { status: 'pending' | 'pass' | 'fail' | 'na'; evidence?: string; auditor?: string },
  ): Promise<AuditChecklistItem> => {
    const { data } = await http.put<AuditChecklistItem>(
      `/api/audit-checklist/${itemId}`,
      req,
    )
    return data
  },
}
