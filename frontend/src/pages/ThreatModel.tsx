/** 威胁建模：项目/资产/威胁清单/缓解控制，支持 LLM 自动生成。 */
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ShieldAlert,
  Plus,
  Sparkles,
  Trash2,
  X,
  Loader2,
  ChevronDown,
  ChevronRight,
  Link2,
  Activity,
} from 'lucide-react'
import { api } from '../api/client'
import type {
  Asset,
  AssetType,
  MitigationControl,
  Threat,
  ThreatCategory,
  ThreatStatus,
} from '../api/types'
import { Card } from '../components/Card'
import { cn, formatDateTime } from '../lib/format'

// ---- 类别与层级常量（与后端一致） ----
const CATEGORY_OPTIONS: { value: ThreatCategory; label: string }[] = [
  { value: 'S', label: 'S · 伪装' },
  { value: 'T', label: 'T · 篡改' },
  { value: 'R', label: 'R · 抵赖' },
  { value: 'I', label: 'I · 信息泄露' },
  { value: 'D', label: 'D · 拒绝服务' },
  { value: 'E', label: 'E · 权限提升' },
  { value: 'prompt_injection', label: 'AI · 提示注入' },
  { value: 'data_poisoning', label: 'AI · 数据投毒' },
  { value: 'model_inversion', label: 'AI · 模型反转' },
  { value: 'alignment_bypass', label: 'AI · 对齐绕过' },
  { value: 'loss_of_provenance', label: 'AI · 来源丢失' },
]

const ASSET_TYPE_LABEL: Record<AssetType, string> = {
  external_entity: '外部实体',
  process: '进程',
  data_store: '数据存储',
  data_flow: '数据流',
  trust_boundary: '信任边界',
}

const REF_LAYER_LABEL: Record<string, string> = {
  lexicon: 'L0 词库',
  prompt_guard: 'L1 注入检测',
  llama_guard: 'L2 危害分类',
  dlp: 'L3 DLP 防泄露',
  cross_verify: 'L4 交叉验证',
  tool_whitelist: '工具白名单',
  rate_limiter: 'API 限流',
  manual: '人工控制',
}

const STATUS_LABEL: Record<ThreatStatus, string> = {
  open: '待处理',
  mitigating: '缓解中',
  mitigated: '已缓解',
  accepted: '已接受',
}

function riskBadge(level: string): string {
  switch (level) {
    case 'Critical':
      return 'bg-rose-100 text-rose-700 border-rose-200'
    case 'High':
      return 'bg-orange-100 text-orange-700 border-orange-200'
    case 'Medium':
      return 'bg-amber-100 text-amber-700 border-amber-200'
    default:
      return 'bg-slate-100 text-slate-600 border-slate-200'
  }
}

function statusBadge(status: ThreatStatus): string {
  switch (status) {
    case 'mitigated':
      return 'bg-emerald-100 text-emerald-700'
    case 'mitigating':
      return 'bg-blue-100 text-blue-700'
    case 'accepted':
      return 'bg-slate-100 text-slate-500'
    default:
      return 'bg-rose-100 text-rose-700'
  }
}

const inputCls = 'w-full rounded-md border border-slate-200 px-3 py-1.5 text-sm focus:border-brand-400 focus:outline-none'

export function ThreatModel() {
  const qc = useQueryClient()
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null)
  const [showProjectForm, setShowProjectForm] = useState(false)
  const [showAssetForm, setShowAssetForm] = useState(false)
  const [editingThreat, setEditingThreat] = useState<Threat | null>(null)
  const [filterStatus, setFilterStatus] = useState<string>('')
  const [filterCategory, setFilterCategory] = useState<string>('')

  // 项目列表
  const { data: projects = [] } = useQuery({
    queryKey: ['threat-projects'],
    queryFn: api.listThreatProjects,
  })

  // 自动选中第一个项目
  const currentProjectId = selectedProjectId ?? projects[0]?.id ?? null

  // 资产
  const { data: assets = [] } = useQuery({
    queryKey: ['threat-assets', currentProjectId],
    queryFn: () => api.listAssets(currentProjectId!),
    enabled: !!currentProjectId,
  })

  // 威胁
  const { data: threats = [] } = useQuery({
    queryKey: ['threats', currentProjectId, filterStatus, filterCategory],
    queryFn: () =>
      api.listThreats(currentProjectId!, {
        status: filterStatus || undefined,
        category: filterCategory || undefined,
      }),
    enabled: !!currentProjectId,
  })

  // LLM 生成
  const generateMut = useMutation({
    mutationFn: () => api.generateThreats(currentProjectId!, false),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['threats', currentProjectId] })
      qc.invalidateQueries({ queryKey: ['threat-projects'] })
    },
  })

  const filteredThreats = useMemo(() => threats, [threats])

  return (
    <div className="space-y-4">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-slate-800">
            <ShieldAlert size={22} className="text-brand-500" />
            威胁建模
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            STRIDE + AI 专属维度的多框架融合威胁分析，支持 LLM 自动生成与缓解证据联动
          </p>
        </div>
      </div>

      {/* 项目选择器 + 操作 */}
      <Card bodyClassName="p-4">
        <div className="flex flex-wrap items-center gap-3">
          <select
            value={currentProjectId ?? ''}
            onChange={(e) => setSelectedProjectId(Number(e.target.value) || null)}
            className={cn(inputCls, 'max-w-xs')}
          >
            {projects.length === 0 && <option value="">暂无项目</option>}
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}（{p.threat_count} 威胁 / {p.open_count} 待处理）
              </option>
            ))}
          </select>

          <button
            onClick={() => setShowProjectForm(true)}
            className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-50"
          >
            <Plus size={14} /> 新建项目
          </button>

          {currentProjectId && (
            <>
              <div className="ml-auto flex items-center gap-2">
                <button
                  onClick={() => generateMut.mutate()}
                  disabled={generateMut.isPending}
                  className="inline-flex items-center gap-1.5 rounded-md bg-brand-500 px-4 py-1.5 text-sm text-white hover:bg-brand-600 disabled:opacity-50"
                >
                  {generateMut.isPending ? (
                    <Loader2 size={14} className="animate-spin" />
                  ) : (
                    <Sparkles size={14} />
                  )}
                  LLM 生成威胁
                </button>
              </div>
            </>
          )}
        </div>

        {generateMut.isError && (
          <div className="mt-3 rounded-md bg-rose-50 p-2 text-xs text-rose-700">
            生成失败：{(generateMut.error as Error)?.message || '请先在「系统设置」中配置威胁建模 LLM'}
          </div>
        )}
        {generateMut.isSuccess && generateMut.data && (
          <div className="mt-3 rounded-md bg-emerald-50 p-2 text-xs text-emerald-700">
            ✓ {generateMut.data.detail}
          </div>
        )}
      </Card>

      {!currentProjectId ? (
        <Card>
          <div className="py-12 text-center text-sm text-slate-400">
            请先创建一个威胁建模项目
          </div>
        </Card>
      ) : (
        <div className="grid grid-cols-12 gap-4">
          {/* 左栏：资产清单 */}
          <div className="col-span-3">
            <AssetPanel
              projectId={currentProjectId}
              assets={assets}
              showForm={showAssetForm}
              setShowForm={setShowAssetForm}
            />
          </div>

          {/* 中栏：威胁清单 */}
          <div className="col-span-5">
            <Card
              title={`威胁清单（${filteredThreats.length}）`}
              actions={
                <div className="flex items-center gap-2">
                  <select
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value)}
                    className="rounded-md border border-slate-200 px-2 py-1 text-xs"
                  >
                    <option value="">全部状态</option>
                    <option value="open">待处理</option>
                    <option value="mitigating">缓解中</option>
                    <option value="mitigated">已缓解</option>
                    <option value="accepted">已接受</option>
                  </select>
                  <select
                    value={filterCategory}
                    onChange={(e) => setFilterCategory(e.target.value)}
                    className="rounded-md border border-slate-200 px-2 py-1 text-xs"
                  >
                    <option value="">全部分类</option>
                    {CATEGORY_OPTIONS.map((c) => (
                      <option key={c.value} value={c.value}>
                        {c.label}
                      </option>
                    ))}
                  </select>
                </div>
              }
              bodyClassName="p-0"
            >
              {filteredThreats.length === 0 ? (
                <div className="py-10 text-center text-sm text-slate-400">
                  暂无威胁。点击右上角「LLM 生成威胁」自动分析，或在详情中手动新增。
                </div>
              ) : (
                <div className="divide-y divide-slate-100">
                  {filteredThreats.map((t) => (
                    <ThreatRow
                      key={t.id}
                      threat={t}
                      isActive={editingThreat?.id === t.id}
                      onClick={() => setEditingThreat(t)}
                    />
                  ))}
                </div>
              )}
            </Card>
          </div>

          {/* 右栏：详情/编辑抽屉 */}
          <div className="col-span-4">
            {editingThreat ? (
              <ThreatDetail
                key={editingThreat.id}
                threat={editingThreat}
                assets={assets}
                onClose={() => setEditingThreat(null)}
              />
            ) : (
              <Card>
                <div className="py-10 text-center text-sm text-slate-400">
                  点击左侧威胁查看详情、编辑评分或关联缓解控制
                </div>
              </Card>
            )}
          </div>
        </div>
      )}

      {/* 新建项目弹窗 */}
      {showProjectForm && (
        <ProjectFormModal
          onClose={() => setShowProjectForm(false)}
          onSaved={(id) => {
            setShowProjectForm(false)
            setSelectedProjectId(id)
          }}
        />
      )}
    </div>
  )
}

// =====================================================================
// 资产面板
// =====================================================================
function AssetPanel({
  projectId,
  assets,
  showForm,
  setShowForm,
}: {
  projectId: number
  assets: Asset[]
  showForm: boolean
  setShowForm: (v: boolean) => void
}) {
  const qc = useQueryClient()
  const [collapsed, setCollapsed] = useState(false)

  const delMut = useMutation({
    mutationFn: (id: number) => api.deleteAsset(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['threat-assets', projectId] }),
  })

  return (
    <Card
      title={`资产（${assets.length}）`}
      actions={
        <button
          onClick={() => setShowForm(!showForm)}
          className="text-xs text-brand-600 hover:underline"
        >
          {showForm ? '取消' : '+ 添加'}
        </button>
      }
      bodyClassName="p-3"
    >
      {showForm && <AssetForm projectId={projectId} onDone={() => setShowForm(false)} />}

      <div className="space-y-1">
        {assets.length === 0 && !showForm && (
          <div className="py-4 text-center text-xs text-slate-400">
            添加资产（外部实体/进程/数据存储等）以帮助 LLM 精准分析
          </div>
        )}
        {!collapsed &&
          assets.map((a) => (
            <div
              key={a.id}
              className="group flex items-start justify-between rounded-md px-2 py-1.5 hover:bg-slate-50"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => setCollapsed(!collapsed)}
                    className="text-slate-300"
                  >
                    <ChevronDown size={12} />
                  </button>
                  <span className="truncate text-sm font-medium text-slate-700">
                    {a.name}
                  </span>
                </div>
                <div className="ml-4 text-[11px] text-slate-400">
                  {ASSET_TYPE_LABEL[a.asset_type]}
                  {a.tech_stack.length > 0 && ` · ${a.tech_stack.join(', ')}`}
                </div>
                {a.description && (
                  <div className="ml-4 mt-0.5 line-clamp-2 text-[11px] text-slate-400">
                    {a.description}
                  </div>
                )}
              </div>
              <button
                onClick={() => delMut.mutate(a.id)}
                className="ml-1 flex-shrink-0 text-slate-300 opacity-0 hover:text-rose-500 group-hover:opacity-100"
              >
                <Trash2 size={13} />
              </button>
            </div>
          ))}
      </div>
    </Card>
  )
}

function AssetForm({ projectId, onDone }: { projectId: number; onDone: () => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [assetType, setAssetType] = useState<AssetType>('process')
  const [techStack, setTechStack] = useState('')

  const mut = useMutation({
    mutationFn: () =>
      api.createAsset(projectId, {
        name,
        description,
        asset_type: assetType,
        tech_stack: techStack
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['threat-assets', projectId] })
      onDone()
    },
  })

  return (
    <div className="mb-2 space-y-2 rounded-md border border-slate-200 bg-slate-50 p-2.5">
      <input
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder="资产名称（如：订单服务）"
        className={inputCls}
      />
      <select
        value={assetType}
        onChange={(e) => setAssetType(e.target.value as AssetType)}
        className={inputCls}
      >
        {(Object.keys(ASSET_TYPE_LABEL) as AssetType[]).map((t) => (
          <option key={t} value={t}>
            {ASSET_TYPE_LABEL[t]}
          </option>
        ))}
      </select>
      <input
        value={techStack}
        onChange={(e) => setTechStack(e.target.value)}
        placeholder="技术栈（逗号分隔，如 Java/Spring, PostgreSQL）"
        className={inputCls}
      />
      <textarea
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        placeholder="描述（可选）"
        rows={2}
        className={inputCls}
      />
      <button
        onClick={() => mut.mutate()}
        disabled={!name || mut.isPending}
        className="w-full rounded-md bg-brand-500 py-1.5 text-xs text-white hover:bg-brand-600 disabled:opacity-50"
      >
        {mut.isPending ? '添加中...' : '添加资产'}
      </button>
    </div>
  )
}

// =====================================================================
// 威胁行
// =====================================================================
function ThreatRow({
  threat,
  isActive,
  onClick,
}: {
  threat: Threat
  isActive: boolean
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-slate-50',
        isActive && 'bg-brand-50/50',
      )}
    >
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              'inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold',
              riskBadge(threat.risk_level),
            )}
          >
            {threat.risk_level}
          </span>
          <span className="truncate text-sm font-medium text-slate-800">
            {threat.title}
          </span>
          {threat.source === 'llm_generated' && (
            <span className="flex-shrink-0 rounded bg-purple-100 px-1 text-[10px] text-purple-600">
              AI
            </span>
          )}
        </div>
        <div className="mt-1 flex items-center gap-2 text-[11px] text-slate-500">
          <span>{CATEGORY_OPTIONS.find((c) => c.value === threat.category)?.label ?? threat.category}</span>
          <span>·</span>
          <span>L{threat.likelihood}×I{threat.impact}</span>
          <span>·</span>
          <span className={cn('rounded px-1', statusBadge(threat.status))}>
            {STATUS_LABEL[threat.status]}
          </span>
        </div>
      </div>
      <ChevronRight size={14} className="mt-1 flex-shrink-0 text-slate-300" />
    </button>
  )
}

// =====================================================================
// 威胁详情 + 缓解控制 + 证据
// =====================================================================
function ThreatDetail({
  threat,
  assets,
  onClose,
}: {
  threat: Threat
  assets: Asset[]
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    title: threat.title,
    description: threat.description,
    category: threat.category,
    likelihood: threat.likelihood,
    impact: threat.impact,
    mitigation: threat.mitigation,
    status: threat.status,
    asset_id: threat.asset_id,
  })

  const saveMut = useMutation({
    mutationFn: () => api.updateThreat(threat.id, form),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['threats'] }),
  })

  const delMut = useMutation({
    mutationFn: () => api.deleteThreat(threat.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['threats'] })
      qc.invalidateQueries({ queryKey: ['threat-projects'] })
      onClose()
    },
  })

  return (
    <Card
      title={
        <div className="flex items-center gap-2">
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600">
            <X size={16} />
          </button>
          <span>威胁详情</span>
          <span
            className={cn(
              'inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold',
              riskBadge(threat.risk_level),
            )}
          >
            {threat.risk_level}
          </span>
        </div>
      }
      actions={
        <button
          onClick={() => delMut.mutate()}
          className="text-slate-400 hover:text-rose-500"
        >
          <Trash2 size={14} />
        </button>
      }
      bodyClassName="p-4"
    >
      <div className="max-h-[calc(100vh-220px)] space-y-3 overflow-y-auto">
        {/* 编辑表单 */}
        <FormField label="标题">
          <input
            value={form.title}
            onChange={(e) => setForm({ ...form, title: e.target.value })}
            className={inputCls}
          />
        </FormField>

        <div className="grid grid-cols-2 gap-2">
          <FormField label="分类">
            <select
              value={form.category}
              onChange={(e) =>
                setForm({ ...form, category: e.target.value as ThreatCategory })
              }
              className={inputCls}
            >
              {CATEGORY_OPTIONS.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </select>
          </FormField>
          <FormField label="关联资产">
            <select
              value={form.asset_id ?? ''}
              onChange={(e) =>
                setForm({ ...form, asset_id: e.target.value ? Number(e.target.value) : null })
              }
              className={inputCls}
            >
              <option value="">（全系统级）</option>
              {assets.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </FormField>
        </div>

        <div className="grid grid-cols-3 gap-2">
          <FormField label={`可能性 L (${form.likelihood})`}>
            <input
              type="range"
              min={1}
              max={5}
              value={form.likelihood}
              onChange={(e) => setForm({ ...form, likelihood: Number(e.target.value) })}
              className="w-full accent-brand-500"
            />
          </FormField>
          <FormField label={`影响 I (${form.impact})`}>
            <input
              type="range"
              min={1}
              max={5}
              value={form.impact}
              onChange={(e) => setForm({ ...form, impact: Number(e.target.value) })}
              className="w-full accent-brand-500"
            />
          </FormField>
          <FormField label="风险等级">
            <div
              className={cn(
                'flex h-[34px] items-center justify-center rounded-md border text-sm font-semibold',
                riskBadge(
                  ((): string => {
                    const s = form.likelihood * form.impact
                    if (s >= 17) return 'Critical'
                    if (s >= 10) return 'High'
                    if (s >= 5) return 'Medium'
                    return 'Low'
                  })(),
                ),
              )}
            >
              {form.likelihood * form.impact}
            </div>
          </FormField>
        </div>

        <FormField label="威胁描述">
          <textarea
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            rows={3}
            className={inputCls}
          />
        </FormField>

        <FormField label="缓解措施">
          <textarea
            value={form.mitigation}
            onChange={(e) => setForm({ ...form, mitigation: e.target.value })}
            rows={3}
            className={inputCls}
          />
        </FormField>

        <FormField label="状态">
          <select
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as ThreatStatus })}
            className={inputCls}
          >
            {(Object.keys(STATUS_LABEL) as ThreatStatus[]).map((s) => (
              <option key={s} value={s}>
                {STATUS_LABEL[s]}
              </option>
            ))}
          </select>
        </FormField>

        <button
          onClick={() => saveMut.mutate()}
          disabled={saveMut.isPending}
          className="w-full rounded-md bg-brand-500 py-1.5 text-sm text-white hover:bg-brand-600 disabled:opacity-50"
        >
          {saveMut.isPending ? '保存中...' : '保存'}
        </button>

        {/* 缓解控制 + 证据 */}
        <div className="border-t border-slate-100 pt-3">
          <ControlPanel threatId={threat.id} />
        </div>
      </div>
    </Card>
  )
}

function FormField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1 block text-xs font-medium text-slate-600">{label}</label>
      {children}
    </div>
  )
}

// =====================================================================
// 缓解控制面板（含证据联动）
// =====================================================================
function ControlPanel({ threatId }: { threatId: number }) {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)

  const { data: controls = [] } = useQuery({
    queryKey: ['controls', threatId],
    queryFn: () => api.listControls(threatId),
  })

  const { data: evidence } = useQuery({
    queryKey: ['evidence', threatId],
    queryFn: () => api.getThreatEvidence(threatId),
    enabled: controls.length > 0,
  })

  const delMut = useMutation({
    mutationFn: (id: number) => api.deleteControl(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['controls', threatId] }),
  })

  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-center gap-1.5 text-xs font-medium text-slate-600">
          <Link2 size={13} />
          缓解控制（{controls.length}）
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="text-xs text-brand-600 hover:underline"
        >
          {showForm ? '取消' : '+ 关联控制'}
        </button>
      </div>

      {showForm && <ControlForm threatId={threatId} onDone={() => setShowForm(false)} />}

      <div className="space-y-2">
        {controls.length === 0 && !showForm && (
          <div className="rounded-md bg-slate-50 p-2 text-center text-[11px] text-slate-400">
            关联现有安全能力（如 L1 注入检测、L3 DLP），查看实际拦截证据
          </div>
        )}
        {controls.map((c) => {
          const ev = evidence?.controls.find((e) => e.control_id === c.id)
          return (
            <ControlItem
              key={c.id}
              control={c}
              evidence={ev}
              onDelete={() => delMut.mutate(c.id)}
            />
          )
        })}
      </div>
    </div>
  )
}

function ControlItem({
  control,
  evidence,
  onDelete,
}: {
  control: MitigationControl
  evidence?: {
    blocked_count_30d: number
    warned_count_30d: number
    total_count_30d: number
    last_triggered: string | null
    note: string
  }
  onDelete: () => void
}) {
  const effBadge: Record<string, string> = {
    verified: 'bg-emerald-100 text-emerald-700',
    in_effect: 'bg-blue-100 text-blue-700',
    planned: 'bg-slate-100 text-slate-500',
    failed: 'bg-rose-100 text-rose-700',
  }
  const effLabel: Record<string, string> = {
    verified: '已验证',
    in_effect: '生效中',
    planned: '计划中',
    failed: '失效',
  }

  return (
    <div className="group rounded-md border border-slate-200 p-2.5">
      <div className="flex items-start justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className="rounded bg-slate-100 px-1 text-[10px] text-slate-600">
              {REF_LAYER_LABEL[control.ref_layer] ?? control.ref_layer}
            </span>
            <span
              className={cn(
                'rounded px-1 text-[10px]',
                effBadge[control.effectiveness] ?? effBadge.planned,
              )}
            >
              {effLabel[control.effectiveness] ?? control.effectiveness}
            </span>
          </div>
          {control.description && (
            <div className="mt-1 text-xs text-slate-600">{control.description}</div>
          )}
          {/* 证据数据 */}
          {evidence && evidence.total_count_30d >= 0 && control.ref_layer !== 'manual' && (
            <div className="mt-1.5 flex items-center gap-2 text-[11px] text-slate-500">
              <Activity size={11} className="text-brand-400" />
              <span>
                近 30 天：拦截 <strong className="text-rose-600">{evidence.blocked_count_30d}</strong>
                {' / '}告警 <strong className="text-amber-600">{evidence.warned_count_30d}</strong>
              </span>
              {evidence.last_triggered && (
                <span className="text-slate-400">
                  · 最后触发 {formatDateTime(evidence.last_triggered)}
                </span>
              )}
            </div>
          )}
          {evidence?.note && (
            <div className="mt-0.5 text-[11px] italic text-slate-400">{evidence.note}</div>
          )}
        </div>
        <button
          onClick={onDelete}
          className="ml-1 flex-shrink-0 text-slate-300 opacity-0 hover:text-rose-500 group-hover:opacity-100"
        >
          <Trash2 size={12} />
        </button>
      </div>
    </div>
  )
}

function ControlForm({ threatId, onDone }: { threatId: number; onDone: () => void }) {
  const qc = useQueryClient()
  const [refLayer, setRefLayer] = useState('prompt_guard')
  const [effectiveness, setEffectiveness] = useState('planned')
  const [description, setDescription] = useState('')

  const mut = useMutation({
    mutationFn: () =>
      api.createControl(threatId, {
        ref_layer: refLayer,
        effectiveness,
        description,
        control_type: 'detection_rule',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['controls', threatId] })
      qc.invalidateQueries({ queryKey: ['evidence', threatId] })
      onDone()
    },
  })

  return (
    <div className="mb-2 space-y-2 rounded-md border border-slate-200 bg-slate-50 p-2.5">
      <select
        value={refLayer}
        onChange={(e) => setRefLayer(e.target.value)}
        className={inputCls}
      >
        {Object.entries(REF_LAYER_LABEL).map(([k, v]) => (
          <option key={k} value={k}>
            {v}
          </option>
        ))}
      </select>
      <select
        value={effectiveness}
        onChange={(e) => setEffectiveness(e.target.value)}
        className={inputCls}
      >
        <option value="planned">计划中</option>
        <option value="in_effect">生效中</option>
        <option value="verified">已验证</option>
        <option value="failed">失效</option>
      </select>
      <input
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        placeholder="控制说明（如：L1 PromptGuard 检测直接注入）"
        className={inputCls}
      />
      <button
        onClick={() => mut.mutate()}
        disabled={mut.isPending}
        className="w-full rounded-md bg-brand-500 py-1.5 text-xs text-white hover:bg-brand-600 disabled:opacity-50"
      >
        {mut.isPending ? '关联中...' : '关联控制'}
      </button>
    </div>
  )
}

// =====================================================================
// 项目创建弹窗
// =====================================================================
function ProjectFormModal({
  onClose,
  onSaved,
}: {
  onClose: () => void
  onSaved: (id: number) => void
}) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [status, setStatus] = useState<'draft' | 'active'>('draft')

  const mut = useMutation({
    mutationFn: () => api.createThreatProject({ name, description, status }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['threat-projects'] })
      onSaved(r.id)
    },
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30">
      <div className="w-96 rounded-xl bg-white p-5 shadow-xl">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-800">新建威胁建模项目</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600">
            <X size={16} />
          </button>
        </div>
        <div className="space-y-3">
          <FormField label="项目名称">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="如：电商订单系统"
              className={inputCls}
              autoFocus
            />
          </FormField>
          <FormField label="系统描述">
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="描述被建模系统的业务、架构与关键数据流，LLM 将据此分析威胁"
              rows={4}
              className={inputCls}
            />
          </FormField>
          <FormField label="状态">
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as 'draft' | 'active')}
              className={inputCls}
            >
              <option value="draft">草稿</option>
              <option value="active">进行中</option>
            </select>
          </FormField>
          <button
            onClick={() => mut.mutate()}
            disabled={!name || mut.isPending}
            className="w-full rounded-md bg-brand-500 py-2 text-sm text-white hover:bg-brand-600 disabled:opacity-50"
          >
            {mut.isPending ? '创建中...' : '创建项目'}
          </button>
        </div>
      </div>
    </div>
  )
}
