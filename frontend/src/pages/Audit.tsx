/** 审计日志：内容审计 + 动作审计（第 3 层应用安全）。 */
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Download, X, ShieldAlert, ScrollText } from 'lucide-react'
import { api } from '../api/client'
import { Card } from '../components/Card'
import { DecisionBadge } from '../components/Badge'
import type { AuditItem } from '../api/types'
import { cn, formatDateTime, formatNumber } from '../lib/format'

const PAGE_SIZE = 20

export function Audit() {
  const [tab, setTab] = useState<'content' | 'actions'>('content')
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-800">审计日志</h1>
        <p className="mt-1 text-sm text-slate-500">内容检测审计 + Agent 动作审计（第 3 层应用安全）</p>
      </div>

      <div className="flex gap-1 border-b border-slate-200">
        <TabButton active={tab === 'content'} onClick={() => setTab('content')} icon={ScrollText} label="内容审计" />
        <TabButton active={tab === 'actions'} onClick={() => setTab('actions')} icon={ShieldAlert} label="动作审计" />
      </div>

      {tab === 'content' ? <ContentAudit /> : <ActionAudit />}
    </div>
  )
}

function TabButton({ active, onClick, icon: Icon, label }: { active: boolean; onClick: () => void; icon: React.ComponentType<{ size?: number | string }>; label: string }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex items-center gap-1.5 border-b-2 px-4 py-2 text-sm font-medium transition-colors',
        active ? 'border-brand-500 text-brand-600' : 'border-transparent text-slate-500 hover:text-slate-700',
      )}
    >
      <Icon size={14} /> {label}
    </button>
  )
}

function ContentAudit() {
  const [page, setPage] = useState(1)
  const [decision, setDecision] = useState('')
  const [source, setSource] = useState('')
  const [days, setDays] = useState(30)
  const [selected, setSelected] = useState<AuditItem | null>(null)

  const { data } = useQuery({
    queryKey: ['audit', page, decision, source, days],
    queryFn: () =>
      api.listAudit({
        page,
        page_size: PAGE_SIZE,
        decision: decision || undefined,
        source: source || undefined,
        days,
      }),
  })

  const items = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-800">审计日志</h1>
          <p className="mt-1 text-sm text-slate-500">共 {formatNumber(total)} 条记录</p>
        </div>
        <a
          href={api.auditCsvUrl(days)}
          className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-50"
        >
          <Download size={14} /> 导出 CSV
        </a>
      </div>

      {/* 过滤 */}
      <Card bodyClassName="flex flex-wrap items-center gap-3">
        <select
          value={decision}
          onChange={(e) => {
            setDecision(e.target.value)
            setPage(1)
          }}
          className="rounded-md border border-slate-200 px-3 py-1.5 text-sm"
        >
          <option value="">全部决策</option>
          <option value="block">拦截</option>
          <option value="warn">警告</option>
          <option value="pass">通过</option>
        </select>
        <select
          value={source}
          onChange={(e) => {
            setSource(e.target.value)
            setPage(1)
          }}
          className="rounded-md border border-slate-200 px-3 py-1.5 text-sm"
        >
          <option value="">全部来源</option>
          <option value="user_prompt">用户输入</option>
          <option value="llm_response">模型输出</option>
          <option value="gateway">网关</option>
          <option value="test">测试</option>
        </select>
        <select
          value={days}
          onChange={(e) => {
            setDays(Number(e.target.value))
            setPage(1)
          }}
          className="rounded-md border border-slate-200 px-3 py-1.5 text-sm"
        >
          <option value={7}>近 7 天</option>
          <option value={30}>近 30 天</option>
          <option value={90}>近 90 天</option>
        </select>
      </Card>

      {/* 列表 */}
      <Card bodyClassName="p-0">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 text-xs text-slate-500">
              <th className="px-4 py-2.5 text-left font-medium">时间</th>
              <th className="px-4 py-2.5 text-left font-medium">来源</th>
              <th className="px-4 py-2.5 text-left font-medium">内容摘要</th>
              <th className="px-4 py-2.5 text-left font-medium">决策</th>
              <th className="px-4 py-2.5 text-left font-medium">风险</th>
              <th className="px-4 py-2.5 text-left font-medium">耗时</th>
            </tr>
          </thead>
          <tbody>
            {items.map((it) => (
              <tr
                key={it.id}
                onClick={() => setSelected(it)}
                className="cursor-pointer border-b border-slate-50 hover:bg-slate-50"
              >
                <td className="px-4 py-2.5 text-xs text-slate-500">
                  {formatDateTime(it.created_at)}
                </td>
                <td className="px-4 py-2.5 text-xs text-slate-500">{it.source}</td>
                <td className="max-w-md truncate px-4 py-2.5 text-slate-700">
                  {it.input_text}
                </td>
                <td className="px-4 py-2.5">
                  <DecisionBadge decision={it.decision} />
                </td>
                <td className="px-4 py-2.5 text-xs text-slate-500">
                  {(it.risk_score * 100).toFixed(0)}%
                </td>
                <td className="px-4 py-2.5 text-xs text-slate-500">{it.latency_ms}ms</td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={6} className="py-12 text-center text-sm text-slate-400">
                  暂无记录
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>

      {/* 分页 */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 text-sm">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="rounded border border-slate-200 px-3 py-1 disabled:opacity-40"
          >
            上一页
          </button>
          <span className="text-slate-500">
            {page} / {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="rounded border border-slate-200 px-3 py-1 disabled:opacity-40"
          >
            下一页
          </button>
        </div>
      )}

      {/* 详情抽屉 */}
      {selected && (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-black/30"
          onClick={() => setSelected(null)}
        >
          <div
            className={cn(
              'h-full w-full max-w-lg overflow-auto bg-white p-6 shadow-xl',
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-base font-semibold text-slate-800">审计详情</h3>
              <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-slate-600">
                <X size={18} />
              </button>
            </div>
            <DetailDrawer item={selected} />
          </div>
        </div>
      )}
    </div>
  )
}

function DetailDrawer({ item }: { item: AuditItem }) {
  return (
    <div className="space-y-4 text-sm">
      <Field label="时间" value={formatDateTime(item.created_at)} />
      <Field label="来源" value={item.source} />
      <Field label="决策">
        <DecisionBadge decision={item.decision} />
      </Field>
      <Field label="风险评分" value={`${(item.risk_score * 100).toFixed(1)}%`} />
      <Field label="耗时" value={`${item.latency_ms} ms`} />
      <div>
        <div className="mb-1 text-xs text-slate-500">原始内容</div>
        <div className="max-h-40 overflow-auto rounded-md bg-slate-50 p-3 text-xs text-slate-600">
          {item.input_text}
        </div>
      </div>
      {item.categories.length > 0 && (
        <div>
          <div className="mb-1 text-xs text-slate-500">命中类别</div>
          <div className="flex flex-wrap gap-1.5">
            {item.categories.map((c, i) => (
              <span key={i} className="rounded bg-rose-100 px-2 py-0.5 text-xs text-rose-700">
                {c}
              </span>
            ))}
          </div>
        </div>
      )}
      {item.explanations.length > 0 && (
        <div>
          <div className="mb-1 text-xs text-slate-500">可解释说明</div>
          <ul className="space-y-1 text-xs text-slate-600">
            {item.explanations.map((e, i) => (
              <li key={i}>• {e}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function Field({
  label,
  value,
  children,
}: {
  label: string
  value?: string
  children?: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-slate-500">{label}</span>
      <span className="text-sm text-slate-700">{value ?? children}</span>
    </div>
  )
}

/** Agent 动作审计（第 3 层应用安全）。 */
function ActionAudit() {
  const [blockedOnly, setBlockedOnly] = useState(false)
  const { data } = useQuery({
    queryKey: ['agent-actions', blockedOnly],
    queryFn: () => api.getAgentActions({ blocked: blockedOnly || undefined, page_size: 50 }),
  })

  const items = data?.items ?? []
  const total = data?.total ?? 0
  const blockedCount = items.filter((i) => i.blocked).length

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <div className="rounded-lg border border-slate-200 bg-white px-4 py-2">
          <span className="text-2xl font-bold text-slate-800">{formatNumber(total)}</span>
          <span className="ml-2 text-xs text-slate-500">总动作数</span>
        </div>
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-2">
          <span className="text-2xl font-bold text-rose-600">{formatNumber(blockedCount)}</span>
          <span className="ml-2 text-xs text-rose-500">被拦截</span>
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-600">
          <input
            type="checkbox"
            checked={blockedOnly}
            onChange={(e) => setBlockedOnly(e.target.checked)}
            className="h-4 w-4 accent-brand-500"
          />
          只看被拦截的
        </label>
      </div>

      <Card bodyClassName="p-0">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 text-xs text-slate-500">
              <th className="px-4 py-2.5 text-left font-medium">时间</th>
              <th className="px-4 py-2.5 text-left font-medium">调用者</th>
              <th className="px-4 py-2.5 text-left font-medium">工具</th>
              <th className="px-4 py-2.5 text-left font-medium">参数摘要</th>
              <th className="px-4 py-2.5 text-left font-medium">状态</th>
              <th className="px-4 py-2.5 text-left font-medium">原因</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && (
              <tr>
                <td colSpan={6} className="py-12 text-center text-sm text-slate-400">
                  暂无动作记录（Agent 调用工具后会出现）
                </td>
              </tr>
            )}
            {items.map((item) => (
              <tr key={item.id} className="border-b border-slate-50 hover:bg-slate-50">
                <td className="px-4 py-2.5 text-xs text-slate-500">{formatDateTime(item.created_at)}</td>
                <td className="px-4 py-2.5 text-xs text-slate-600">{item.subject}</td>
                <td className="px-4 py-2.5">
                  <code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs font-mono text-slate-700">
                    {item.tool_name}
                  </code>
                </td>
                <td className="max-w-xs truncate px-4 py-2.5 text-xs text-slate-500">
                  {item.arguments_summary || '-'}
                </td>
                <td className="px-4 py-2.5">
                  {item.blocked ? (
                    <span className="rounded-full bg-rose-100 px-2 py-0.5 text-xs text-rose-700">已拦截</span>
                  ) : (
                    <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs text-emerald-700">已放行</span>
                  )}
                </td>
                <td className="max-w-xs truncate px-4 py-2.5 text-xs text-slate-500">
                  {item.block_reason || '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  )
}
