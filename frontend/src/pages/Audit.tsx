/** 审计日志：列表 + 过滤 + 详情抽屉 + CSV 导出。 */
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Download, X } from 'lucide-react'
import { api } from '../api/client'
import { Card } from '../components/Card'
import { DecisionBadge } from '../components/Badge'
import type { AuditItem } from '../api/types'
import { cn, formatDateTime, formatNumber } from '../lib/format'

const PAGE_SIZE = 20

export function Audit() {
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
