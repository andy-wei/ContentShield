/**
 * LLM 红队对抗测试页面。
 *
 * 布局：
 * - 左栏：活动列表（创建 + 管理）
 * - 右栏：活动报告（ASR、类别分布、成功攻击 Top、风险洞察）
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Swords,
  Plus,
  Trash2,
  Loader2,
  Target,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react'
import { api } from '../api/client'
import type { Campaign, AttackResult } from '../api/types'
import { Card } from '../components/Card'
import { cn, formatDateTime } from '../lib/format'

const STATUS_STYLE: Record<string, { badge: string; label: string }> = {
  pending: { badge: 'bg-slate-100 text-slate-600', label: '等待' },
  running: { badge: 'bg-blue-100 text-blue-700', label: '运行中' },
  completed: { badge: 'bg-emerald-100 text-emerald-700', label: '完成' },
  failed: { badge: 'bg-rose-100 text-rose-700', label: '失败' },
}

const CATEGORY_LABEL: Record<string, string> = {
  jailbreak: '越狱',
  prompt_injection: '注入',
  harmful_request: '有害请求',
  encoding: '编码绕过',
  social_engineering: '社会工程',
}

export function Redteam() {
  const qc = useQueryClient()
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [tab, setTab] = useState<'adversarial' | 'membership'>('adversarial')

  const campaignsQuery = useQuery({
    queryKey: ['campaigns'],
    queryFn: api.listCampaigns,
    refetchInterval: (query) => {
      const campaigns = query.state.data || []
      return campaigns.some((c) => c.status === 'running' || c.status === 'pending')
        ? 5000
        : false
    },
  })

  const deleteMut = useMutation({
    mutationFn: api.deleteCampaign,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['campaigns'] }),
  })

  const campaigns = campaignsQuery.data || []

  return (
    <div className="space-y-4">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold text-slate-800">
            <Swords className="h-5 w-5 text-brand-500" />
            红队对抗测试
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            LLM 安全评估 · 自动化攻击生成 + Llama-Guard judge + ASR 评估
          </p>
        </div>
        {tab === 'adversarial' && (
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1 rounded-lg bg-brand-500 px-3 py-1.5 text-sm text-white hover:bg-brand-600"
          >
            <Plus className="h-4 w-4" /> 发起测试
          </button>
        )}
      </div>

      {/* Tab 切换：对抗测试 / 成员推理 */}
      <div className="flex gap-1 border-b border-slate-200">
        <TabButton active={tab === 'adversarial'} onClick={() => setTab('adversarial')}>
          ⚔️ 对抗测试（ASR）
        </TabButton>
        <TabButton active={tab === 'membership'} onClick={() => setTab('membership')}>
          🔬 成员推理（MIA）
        </TabButton>
      </div>

      {tab === 'membership' ? (
        <MembershipInferenceView />
      ) : (
        <div className="grid grid-cols-12 gap-4">
          {/* 左栏：活动列表 */}
          <div className="col-span-4">
            <Card title="测试活动">
              <div className="space-y-1">
                {campaigns.length === 0 && (
                  <p className="py-6 text-center text-sm text-slate-400">
                    暂无活动，点击「发起测试」
                  </p>
                )}
                {campaigns.map((c) => (
                  <CampaignRow
                    key={c.id}
                    campaign={c}
                  selected={selectedId === c.id}
                  onSelect={() => setSelectedId(c.id)}
                  onDelete={() => deleteMut.mutate(c.id)}
                />
              ))}
            </div>
          </Card>
        </div>

        {/* 右栏：报告 */}
        <div className="col-span-8">
          {selectedId ? (
            <CampaignReportView campaignId={selectedId} />
          ) : (
            <Card>
              <p className="py-12 text-center text-sm text-slate-400">
                选择一个活动查看报告，或发起新测试
              </p>
            </Card>
          )}
        </div>
      </div>
      )}

      {showCreate && (
        <CreateCampaignForm
          onCancel={() => setShowCreate(false)}
          onSuccess={() => {
            setShowCreate(false)
            qc.invalidateQueries({ queryKey: ['campaigns'] })
          }}
        />
      )}
    </div>
  )
}

// ==================== Tab 按钮 ====================

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        '-mb-px border-b-2 px-4 py-2 text-sm font-medium transition',
        active
          ? 'border-brand-500 text-brand-600'
          : 'border-transparent text-slate-500 hover:text-slate-700',
      )}
    >
      {children}
    </button>
  )
}

// ==================== 成员推理视图 ====================

function MembershipInferenceView() {
  const [targetModel, setTargetModel] = useState('gpt-4o-mini')
  const [baseUrl, setBaseUrl] = useState('https://api.openai.com/v1')
  const [apiKey, setApiKey] = useState('')
  const [name, setName] = useState('')
  const [loading, setLoading] = useState(false)
  const [resultId, setResultId] = useState<number | null>(null)
  const qc = useQueryClient()

  const resultQuery = useQuery({
    queryKey: ['mia-result', resultId],
    queryFn: () => api.getMIA(resultId!),
    enabled: !!resultId,
    refetchInterval: (query) => {
      const data = query.state.data
      return data && (data.status === 'running' || data.status === 'pending') ? 5000 : false
    },
  })

  const submit = async () => {
    if (!apiKey || !name) return
    setLoading(true)
    try {
      const res = await api.createMIA({
        name,
        target_base_url: baseUrl,
        target_api_key: apiKey,
        target_model: targetModel,
      })
      setResultId(res.campaign_id)
      qc.invalidateQueries({ queryKey: ['campaigns'] })
    } finally {
      setLoading(false)
    }
  }

  const result = resultQuery.data
  const riskColor =
    result?.risk_level === 'critical'
      ? 'text-rose-600'
      : result?.risk_level === 'high'
        ? 'text-orange-600'
        : result?.risk_level === 'medium'
          ? 'text-amber-600'
          : 'text-emerald-600'

  return (
    <div className="space-y-4">
      {/* 发起 MIA */}
      <Card title="成员推理攻击（Membership Inference）">
        <p className="mb-3 text-sm text-slate-500">
          通过对比模型对「训练集成员」vs「非成员」探针的响应差异，
          评估模型是否泄露训练数据成员关系。MI Advantage 越高 = 隐私泄露风险越大。
        </p>
        <div className="grid grid-cols-2 gap-3">
          <Field label="活动名称">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="如：GPT-4o 成员推理评估"
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            />
          </Field>
          <Field label="目标模型">
            <input
              value={targetModel}
              onChange={(e) => setTargetModel(e.target.value)}
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            />
          </Field>
          <Field label="Base URL">
            <input
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            />
          </Field>
          <Field label="API Key">
            <input
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              type="password"
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            />
          </Field>
        </div>
        <button
          onClick={submit}
          disabled={!name || !apiKey || loading}
          className="mt-3 flex items-center gap-1 rounded-lg bg-brand-500 px-4 py-1.5 text-sm text-white hover:bg-brand-600 disabled:opacity-40"
        >
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
          发起成员推理测试
        </button>
      </Card>

      {/* 结果 */}
      {result && (
        <>
          <Card title="成员推理分析结果">
            <div className="flex items-center gap-8">
              <div className="text-center">
                <div className={cn('text-4xl font-bold', riskColor)}>
                  {(result.mi_advantage * 100).toFixed(1)}%
                </div>
                <div className="mt-1 text-xs text-slate-400">MI Advantage</div>
              </div>
              <div className="flex-1 space-y-1 text-sm">
                <div className="flex justify-between">
                  <span className="text-slate-500">风险等级</span>
                  <span className={cn('font-medium', riskColor)}>{result.risk_level}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">certainty 差距</span>
                  <span className="font-medium">{result.certainty_gap.toFixed(3)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">member 平均确定性</span>
                  <span className="font-medium">{result.member_avg_certainty.toFixed(3)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">non-member 平均确定性</span>
                  <span className="font-medium">{result.nonmember_avg_certainty.toFixed(3)}</span>
                </div>
              </div>
            </div>
            <div className="mt-3 rounded-md bg-slate-50 px-3 py-2 text-xs text-slate-600">
              {result.interpretation}
            </div>
          </Card>

          {/* 探针明细 */}
          {result.per_probe.length > 0 && (
            <Card title="探针响应明细">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 text-left text-xs text-slate-400">
                    <th className="py-2 pr-2 font-medium">类型</th>
                    <th className="py-2 pr-2 font-medium">探针文本</th>
                    <th className="py-2 pr-2 font-medium">确定性</th>
                    <th className="py-2 pr-2 font-medium">回复长度</th>
                  </tr>
                </thead>
                <tbody>
                  {result.per_probe.map((p, i) => (
                    <tr key={i} className="border-b border-slate-50">
                      <td className="py-2 pr-2">
                        <span
                          className={cn(
                            'rounded px-1.5 py-0.5 text-xs',
                            p.is_member
                              ? 'bg-blue-100 text-blue-700'
                              : 'bg-slate-100 text-slate-600',
                          )}
                        >
                          {p.is_member ? 'member' : 'non-member'}
                        </span>
                      </td>
                      <td className="py-2 pr-2 text-xs text-slate-600">{p.text}</td>
                      <td className="py-2 pr-2 text-xs font-medium">{p.certainty.toFixed(3)}</td>
                      <td className="py-2 pr-2 text-xs text-slate-500">{p.response_length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          )}
        </>
      )}
    </div>
  )
}

// ==================== 活动行 ====================

function CampaignRow({
  campaign,
  selected,
  onSelect,
  onDelete,
}: {
  campaign: Campaign
  selected: boolean
  onSelect: () => void
  onDelete: () => void
}) {
  const status = STATUS_STYLE[campaign.status] || STATUS_STYLE.pending
  const asrPct = (campaign.asr * 100).toFixed(0)
  const asrColor =
    campaign.asr >= 0.5
      ? 'text-rose-600'
      : campaign.asr >= 0.2
        ? 'text-amber-600'
        : 'text-emerald-600'

  return (
    <div
      onClick={onSelect}
      className={cn(
        'group flex cursor-pointer items-center justify-between rounded-lg border px-3 py-2 text-sm',
        selected ? 'border-brand-300 bg-brand-50' : 'border-transparent hover:bg-slate-50',
      )}
    >
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="font-medium text-slate-700">{campaign.name}</span>
          <span className={cn('rounded px-1.5 py-0.5 text-xs font-medium', status.badge)}>
            {status.label}
          </span>
          {campaign.status === 'running' && (
            <Loader2 className="h-3 w-3 animate-spin text-blue-600" />
          )}
        </div>
        <div className="mt-0.5 text-xs text-slate-400">
          {formatDateTime(campaign.created_at)} · {campaign.total_attacks} 攻击
        </div>
      </div>
      {campaign.status === 'completed' && (
        <div className="text-right">
          <div className={cn('text-sm font-bold', asrColor)}>{asrPct}%</div>
          <div className="text-xs text-slate-400">ASR</div>
        </div>
      )}
      <button
        onClick={(e) => {
          e.stopPropagation()
          onDelete()
        }}
        className="ml-2 opacity-0 transition group-hover:opacity-100"
      >
        <Trash2 className="h-4 w-4 text-rose-400 hover:text-rose-600" />
      </button>
    </div>
  )
}

// ==================== 报告视图 ====================

function CampaignReportView({ campaignId }: { campaignId: number }) {
  const reportQuery = useQuery({
    queryKey: ['campaign-report', campaignId],
    queryFn: () => api.getCampaignReport(campaignId),
    enabled: !!campaignId,
  })

  if (reportQuery.isLoading) {
    return (
      <Card>
        <div className="flex items-center justify-center py-12 text-slate-400">
          <Loader2 className="mr-2 h-5 w-5 animate-spin" /> 加载报告...
        </div>
      </Card>
    )
  }

  if (reportQuery.isError || !reportQuery.data) {
    return (
      <Card>
        <p className="py-12 text-center text-sm text-rose-400">报告加载失败</p>
      </Card>
    )
  }

  const report = reportQuery.data
  const asrPct = (report.overall_asr * 100).toFixed(1)
  const asrColor =
    report.overall_asr >= 0.5
      ? 'text-rose-600'
      : report.overall_asr >= 0.2
        ? 'text-amber-600'
        : 'text-emerald-600'

  return (
    <div className="space-y-4">
      {/* ASR 概览 */}
      <Card title="攻击成功率（ASR）">
        <div className="flex items-center gap-8">
          <div className="text-center">
            <div className={cn('text-4xl font-bold', asrColor)}>{asrPct}%</div>
            <div className="mt-1 text-xs text-slate-400">整体 ASR</div>
          </div>
          <div className="flex-1 space-y-1 text-sm">
            <div className="flex justify-between">
              <span className="text-slate-500">总攻击数</span>
              <span className="font-medium">{report.campaign.total_attacks}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">成功越狱</span>
              <span className="font-medium text-rose-600">
                {report.campaign.success_count}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">目标模型</span>
              <span className="font-medium">
                {report.campaign.target_config.model}
              </span>
            </div>
          </div>
        </div>
      </Card>

      {/* 类别分布 */}
      <Card title="按攻击类别分布">
        <div className="space-y-2">
          {Object.entries(report.category_breakdown).map(([cat, stats]) => (
            <CategoryBar
              key={cat}
              category={cat}
              total={stats.total}
              success={stats.success}
              asr={stats.asr}
            />
          ))}
          {Object.keys(report.category_breakdown).length === 0 && (
            <p className="py-4 text-center text-sm text-slate-400">暂无数据</p>
          )}
        </div>
      </Card>

      {/* 风险洞察 */}
      {report.risk_insights.length > 0 && (
        <Card title="风险洞察">
          <ul className="space-y-2">
            {report.risk_insights.map((insight, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-600">
                <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-500" />
                <span>{insight}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {/* 成功攻击 Top */}
      <Card title="成功越狱案例" subtitle={`Top ${report.top_successful_attacks.length}`}>
        <div className="space-y-2">
          {report.top_successful_attacks.map((r) => (
            <SuccessAttackRow key={r.id} result={r} />
          ))}
          {report.top_successful_attacks.length === 0 && (
            <p className="flex items-center justify-center gap-1 py-4 text-sm text-emerald-600">
              <CheckCircle2 className="h-4 w-4" /> 无成功越狱，模型防御良好
            </p>
          )}
        </div>
      </Card>
    </div>
  )
}

function CategoryBar({
  category,
  total,
  success,
  asr,
}: {
  category: string
  total: number
  success: number
  asr: number
}) {
  const pct = (asr * 100).toFixed(0)
  const barColor = asr >= 0.5 ? 'bg-rose-500' : asr >= 0.2 ? 'bg-amber-500' : 'bg-emerald-500'

  return (
    <div className="flex items-center gap-3">
      <div className="w-24 text-sm text-slate-600">
        {CATEGORY_LABEL[category] || category}
      </div>
      <div className="h-6 flex-1 overflow-hidden rounded bg-slate-100">
        <div
          className={cn('h-full rounded', barColor)}
          style={{ width: `${Math.max(Number(pct), 2)}%` }}
        />
      </div>
      <div className="w-32 text-right text-xs text-slate-500">
        {success}/{total} · {pct}%
      </div>
    </div>
  )
}

function SuccessAttackRow({ result }: { result: AttackResult }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="rounded-lg border border-rose-100 bg-rose-50/50 p-3">
      <div
        onClick={() => setExpanded(!expanded)}
        className="cursor-pointer"
      >
        <div className="flex items-center gap-2">
          <span className="rounded bg-rose-100 px-1.5 py-0.5 text-xs text-rose-700">
            {result.case ? CATEGORY_LABEL[result.case.category] || result.case.category : ''}
          </span>
          <span className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-500">
            {result.case?.source}
          </span>
          {result.judged_category && (
            <span className="text-xs text-rose-600">→ {result.judged_category}</span>
          )}
          <span className="ml-auto text-xs text-slate-400">
            {result.latency_ms}ms
          </span>
        </div>
        <div className="mt-1 truncate text-sm text-slate-700">
          {result.case?.prompt}
        </div>
      </div>
      {expanded && (
        <div className="mt-2 space-y-2 border-t border-rose-100 pt-2">
          <div>
            <div className="text-xs font-medium text-slate-500">攻击 prompt:</div>
            <div className="mt-0.5 whitespace-pre-wrap text-xs text-slate-600">
              {result.case?.prompt}
            </div>
          </div>
          <div>
            <div className="text-xs font-medium text-rose-600">目标回复（被判不安全）:</div>
            <div className="mt-0.5 whitespace-pre-wrap text-xs text-slate-600">
              {result.response}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ==================== 创建活动表单 ====================

function CreateCampaignForm({
  onCancel,
  onSuccess,
}: {
  onCancel: () => void
  onSuccess: () => void
}) {
  const [name, setName] = useState('')
  const [model, setModel] = useState('gpt-4o-mini')
  const [baseUrl, setBaseUrl] = useState('https://api.openai.com/v1')
  const [apiKey, setApiKey] = useState('')
  const [source, setSource] = useState<'preset' | 'template' | 'mixed'>('preset')
  const [count, setCount] = useState(10)
  const [loading, setLoading] = useState(false)

  const submit = async () => {
    if (!name || !model) return
    setLoading(true)
    try {
      await api.createCampaign({
        name,
        target: { base_url: baseUrl, api_key: apiKey, model, temperature: 0.7, max_tokens: 512 },
        strategy: { source, count, categories: [] },
      })
      onSuccess()
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30">
      <Card title="发起红队测试" className="max-h-[90vh] w-full max-w-lg overflow-y-auto">
        <div className="space-y-3">
          <Field label="活动名称">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="如：GPT-4o 安全评估"
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            />
          </Field>

          <div className="rounded-lg bg-slate-50 p-3">
            <div className="mb-2 flex items-center gap-1 text-sm font-medium text-slate-700">
              <Target className="h-4 w-4" /> 目标模型
            </div>
            <div className="grid grid-cols-2 gap-2">
              <Field label="模型名称">
                <input
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
                />
              </Field>
              <Field label="API Key">
                <input
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  type="password"
                  placeholder="sk-..."
                  className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
                />
              </Field>
            </div>
            <Field label="Base URL">
              <input
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
              />
            </Field>
          </div>

          <div className="rounded-lg bg-slate-50 p-3">
            <div className="mb-2 flex items-center gap-1 text-sm font-medium text-slate-700">
              <TrendingUp className="h-4 w-4" /> 攻击策略
            </div>
            <div className="grid grid-cols-2 gap-2">
              <Field label="攻击来源">
                <select
                  value={source}
                  onChange={(e) => setSource(e.target.value as 'preset' | 'template' | 'mixed')}
                  className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
                >
                  <option value="preset">预设测试集</option>
                  <option value="template">模板生成</option>
                  <option value="mixed">混合</option>
                </select>
              </Field>
              <Field label="攻击数量">
                <input
                  type="number"
                  value={count}
                  onChange={(e) => setCount(Number(e.target.value))}
                  min={1}
                  max={100}
                  className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
                />
              </Field>
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              onClick={onCancel}
              className="rounded-lg px-3 py-1.5 text-sm text-slate-500 hover:bg-slate-100"
            >
              取消
            </button>
            <button
              onClick={submit}
              disabled={!name || !model || loading}
              className="rounded-lg bg-brand-500 px-3 py-1.5 text-sm text-white hover:bg-brand-600 disabled:opacity-40"
            >
              {loading ? '创建中...' : '开始测试'}
            </button>
          </div>
        </div>
      </Card>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1 block text-xs font-medium text-slate-600">{label}</label>
      {children}
    </div>
  )
}
