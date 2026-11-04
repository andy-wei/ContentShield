/**
 * OWASP LLM Top 10 审计 checklist 页面。
 *
 * 把 OWASP LLM Top 10（2025）的 10 类风险固化为可逐项审计的 checklist，
 * 每项含审计要点、检查方法、对应检测层、状态跟踪。
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ClipboardCheck,
  CheckCircle2,
  XCircle,
  Circle,
  MinusCircle,
  ShieldAlert,
} from 'lucide-react'
import { api } from '../api/client'
import type { AuditChecklistItem, ChecklistStatus } from '../api/types'
import { Card } from '../components/Card'
import { cn } from '../lib/format'

const STATUS_CONFIG: Record<
  ChecklistStatus,
  { label: string; badge: string; icon: typeof CheckCircle2 }
> = {
  pending: { label: '待审计', badge: 'bg-slate-100 text-slate-600', icon: Circle },
  pass: { label: '通过', badge: 'bg-emerald-100 text-emerald-700', icon: CheckCircle2 },
  fail: { label: '不通过', badge: 'bg-rose-100 text-rose-700', icon: XCircle },
  na: { label: '不适用', badge: 'bg-slate-100 text-slate-400', icon: MinusCircle },
}

const METHOD_LABEL: Record<string, string> = {
  code_review: '代码审计',
  config_check: '配置检查',
  tool_scan: '工具扫描',
  pentest: '渗透测试',
}

const REF_LAYER_LABEL: Record<string, string> = {
  prompt_guard: 'L1 注入检测',
  dlp: 'L3 DLP',
  llama_guard: 'L2 危害分类',
  indirect_injection: 'L1.5 间接注入',
  tool_whitelist: '工具白名单',
  cross_verify: 'L4 交叉验证',
  code_shield: 'L5 代码安全',
  alignment_check: '行为对齐检测',
  rate_limiter: '限流',
  manual: '人工',
}

export function AuditChecklist() {
  const qc = useQueryClient()
  const [expandedId, setExpandedId] = useState<number | null>(null)

  const summaryQuery = useQuery({
    queryKey: ['checklist-summary'],
    queryFn: api.getChecklistSummary,
  })

  const itemsQuery = useQuery({
    queryKey: ['checklist-items'],
    queryFn: () => api.listChecklist(),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, ...req }: { id: number } & Parameters<typeof api.updateChecklistItem>[1]) =>
      api.updateChecklistItem(id, req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['checklist-items'] })
      qc.invalidateQueries({ queryKey: ['checklist-summary'] })
    },
  })

  const summary = summaryQuery.data
  const items = itemsQuery.data || []
  const passRatePct = summary ? (summary.pass_rate * 100).toFixed(0) : '0'
  const passRateColor =
    Number(passRatePct) >= 80
      ? 'text-emerald-600'
      : Number(passRatePct) >= 50
        ? 'text-amber-600'
        : 'text-rose-600'

  return (
    <div className="space-y-4">
      {/* 页头 */}
      <div>
        <h1 className="flex items-center gap-2 text-xl font-semibold text-slate-800">
          <ClipboardCheck className="h-5 w-5 text-brand-500" />
          安全审计 Checklist
        </h1>
        <p className="mt-1 text-sm text-slate-500">
          OWASP LLM Top 10（2025）· AI 原生应用全生命周期安全审计 · 映射到系统检测层
        </p>
      </div>

      {/* 进度摘要 */}
      {summary && (
        <div className="grid grid-cols-6 gap-3">
          <Card>
            <div className="text-center">
              <div className={cn('text-3xl font-bold', passRateColor)}>{passRatePct}%</div>
              <div className="mt-0.5 text-xs text-slate-400">审计通过率</div>
            </div>
          </Card>
          <SummaryCard label="总项数" value={summary.total} color="text-slate-700" />
          <SummaryCard label="通过" value={summary.pass_count} color="text-emerald-600" />
          <SummaryCard label="不通过" value={summary.fail_count} color="text-rose-600" />
          <SummaryCard label="待审计" value={summary.pending_count} color="text-amber-600" />
          <SummaryCard label="不适用" value={summary.na_count} color="text-slate-400" />
        </div>
      )}

      {/* Checklist 列表 */}
      <Card title="OWASP LLM Top 10 审计项">
        <div className="space-y-2">
          {items.map((item) => (
            <ChecklistRow
              key={item.id}
              item={item}
              expanded={expandedId === item.id}
              onToggle={() => setExpandedId(expandedId === item.id ? null : item.id)}
              onUpdate={(status) =>
                updateMut.mutate({ id: item.id, status })
              }
            />
          ))}
        </div>
      </Card>
    </div>
  )
}

function SummaryCard({
  label,
  value,
  color,
}: {
  label: string
  value: number
  color: string
}) {
  return (
    <Card>
      <div className="text-center">
        <div className={cn('text-2xl font-bold', color)}>{value}</div>
        <div className="mt-0.5 text-xs text-slate-400">{label}</div>
      </div>
    </Card>
  )
}

function ChecklistRow({
  item,
  expanded,
  onToggle,
  onUpdate,
}: {
  item: AuditChecklistItem
  expanded: boolean
  onToggle: () => void
  onUpdate: (status: ChecklistStatus) => void
}) {
  const statusCfg = STATUS_CONFIG[item.status] || STATUS_CONFIG.pending
  const StatusIcon = statusCfg.icon

  return (
    <div className="rounded-lg border border-slate-100">
      {/* 头部 */}
      <div
        onClick={onToggle}
        className="flex cursor-pointer items-center gap-3 px-3 py-2.5 hover:bg-slate-50"
      >
        <span className="font-mono text-xs font-bold text-brand-500">{item.owasp_id}</span>
        <StatusIcon
          className={cn(
            'h-4 w-4 flex-shrink-0',
            item.status === 'pass' && 'text-emerald-500',
            item.status === 'fail' && 'text-rose-500',
            item.status === 'pending' && 'text-slate-300',
            item.status === 'na' && 'text-slate-300',
          )}
        />
        <div className="min-w-0 flex-1">
          <span className="text-sm font-medium text-slate-700">{item.name}</span>
        </div>
        <span className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-500">
          {METHOD_LABEL[item.check_method] || item.check_method}
        </span>
        <span className="rounded bg-blue-50 px-1.5 py-0.5 text-xs text-blue-600">
          {REF_LAYER_LABEL[item.ref_layer] || item.ref_layer}
        </span>
        <span className={cn('rounded px-1.5 py-0.5 text-xs font-medium', statusCfg.badge)}>
          {statusCfg.label}
        </span>
      </div>

      {/* 展开详情 */}
      {expanded && (
        <div className="border-t border-slate-100 bg-slate-50/50 px-3 py-3">
          {/* 审计要点 */}
          <div className="mb-3">
            <div className="mb-1 text-xs font-medium text-slate-500">审计要点：</div>
            <ul className="space-y-1">
              {item.audit_points.map((point, i) => (
                <li key={i} className="flex items-start gap-1.5 text-xs text-slate-600">
                  <span className="mt-0.5 text-brand-400">▸</span>
                  <span>{point}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* 审计证据 */}
          {item.evidence && (
            <div className="mb-3 rounded bg-white px-2 py-1.5 text-xs">
              <span className="font-medium text-slate-500">证据/备注：</span>
              <span className="text-slate-600">{item.evidence}</span>
              {item.auditor && (
                <span className="ml-2 text-slate-400">— {item.auditor}</span>
              )}
            </div>
          )}

          {/* 状态操作按钮 */}
          <div className="flex gap-2">
            {(['pending', 'pass', 'fail', 'na'] as ChecklistStatus[]).map((s) => {
              const cfg = STATUS_CONFIG[s]
              const Icon = cfg.icon
              return (
                <button
                  key={s}
                  onClick={(e) => {
                    e.stopPropagation()
                    onUpdate(s)
                  }}
                  className={cn(
                    'flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs transition',
                    item.status === s
                      ? cfg.badge + ' ring-2 ring-offset-1'
                      : 'border-slate-200 text-slate-500 hover:bg-slate-100',
                  )}
                >
                  <Icon className="h-3 w-3" />
                  {cfg.label}
                </button>
              )
            })}
          </div>

          {/* fail 时显示风险提示 */}
          {item.status === 'fail' && (
            <div className="mt-2 flex items-center gap-1 rounded bg-rose-50 px-2 py-1 text-xs text-rose-600">
              <ShieldAlert className="h-3 w-3" />
              该项审计未通过，存在安全风险，需修复后复审
            </div>
          )}
        </div>
      )}
    </div>
  )
}
