/**
 * 安全扫描页面：DevSecOps 漏洞扫描平台。
 *
 * 布局：
 * - 顶部：新建扫描（选目标 + 工具）+ 工具可用性展示
 * - 左栏：扫描目标列表（CRUD）
 * - 右栏：扫描任务列表 + 任务详情（finding 表格 + 门禁判定）
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ScanSearch,
  Plus,
  Trash2,
  Play,
  X,
  Loader2,
  CheckCircle2,
  XCircle,
  ShieldCheck,
  ShieldAlert,
} from 'lucide-react'
import { api } from '../api/client'
import type {
  ScanTarget,
  ScanJobSummary,
  Finding,
  Severity,
} from '../api/types'
import { Card } from '../components/Card'
import { cn, formatDateTime } from '../lib/format'

// 严重度样式映射
const SEVERITY_STYLE: Record<Severity, { badge: string; label: string }> = {
  critical: { badge: 'bg-rose-100 text-rose-700 border-rose-200', label: 'Critical' },
  high: { badge: 'bg-orange-100 text-orange-700 border-orange-200', label: 'High' },
  medium: { badge: 'bg-amber-100 text-amber-700 border-amber-200', label: 'Medium' },
  low: { badge: 'bg-sky-100 text-sky-700 border-sky-200', label: 'Low' },
  info: { badge: 'bg-slate-100 text-slate-600 border-slate-200', label: 'Info' },
}

const STATUS_STYLE: Record<string, { badge: string; label: string }> = {
  pending: { badge: 'bg-slate-100 text-slate-600', label: '等待' },
  running: { badge: 'bg-blue-100 text-blue-700', label: '运行中' },
  completed: { badge: 'bg-emerald-100 text-emerald-700', label: '完成' },
  failed: { badge: 'bg-rose-100 text-rose-700', label: '失败' },
  canceled: { badge: 'bg-slate-100 text-slate-500', label: '已取消' },
}

export function ScanJobs() {
  const qc = useQueryClient()
  const [selectedTargetId, setSelectedTargetId] = useState<number | null>(null)
  const [selectedJobId, setSelectedJobId] = useState<number | null>(null)
  const [showNewTarget, setShowNewTarget] = useState(false)
  const [showNewScan, setShowNewScan] = useState(false)

  // 目标列表
  const targetsQuery = useQuery({
    queryKey: ['scan-targets'],
    queryFn: api.listScanTargets,
  })

  // 工具列表
  const toolsQuery = useQuery({
    queryKey: ['scan-tools'],
    queryFn: api.listScanTools,
  })

  // 任务列表（按选中目标过滤）
  const jobsQuery = useQuery({
    queryKey: ['scan-jobs', selectedTargetId],
    queryFn: () => api.listScanJobs(selectedTargetId ? { target_id: selectedTargetId } : undefined),
    refetchInterval: (query) => {
      // 有运行中/等待中的任务时 5 秒轮询
      const jobs = query.state.data || []
      return jobs.some((j) => j.status === 'running' || j.status === 'pending') ? 5000 : false
    },
  })

  // 新建目标
  const createTargetMut = useMutation({
    mutationFn: api.createScanTarget,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-targets'] })
      setShowNewTarget(false)
    },
  })

  // 删除目标
  const deleteTargetMut = useMutation({
    mutationFn: api.deleteScanTarget,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan-targets'] }),
  })

  // 新建扫描
  const createJobMut = useMutation({
    mutationFn: api.createScanJob,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-jobs'] })
      setShowNewScan(false)
    },
  })

  // 取消任务
  const cancelJobMut = useMutation({
    mutationFn: api.cancelScanJob,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan-jobs'] }),
  })

  const targets = targetsQuery.data || []
  const jobs = jobsQuery.data || []
  const tools = toolsQuery.data || []
  const availableTools = tools.filter((t) => t.available).map((t) => t.name)

  return (
    <div className="space-y-4">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold text-slate-800">
            <ScanSearch className="h-5 w-5 text-brand-500" />
            安全扫描
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            DevSecOps 漏洞扫描编排平台 · 编排 bandit / gitleaks / trivy / pip-audit
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowNewTarget(true)}
            className="flex items-center gap-1 rounded-lg border border-slate-200 px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-50"
          >
            <Plus className="h-4 w-4" /> 新建目标
          </button>
          <button
            onClick={() => setShowNewScan(true)}
            disabled={targets.length === 0}
            className="flex items-center gap-1 rounded-lg bg-brand-500 px-3 py-1.5 text-sm text-white hover:bg-brand-600 disabled:opacity-40"
          >
            <Play className="h-4 w-4" /> 发起扫描
          </button>
        </div>
      </div>

      {/* 工具可用性 */}
      <Card>
        <div className="flex flex-wrap gap-2">
          {tools.map((t) => (
            <span
              key={t.name}
              className={cn(
                'inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs',
                t.available
                  ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
                  : 'border-slate-200 bg-slate-50 text-slate-400',
              )}
              title={t.description}
            >
              {t.available ? (
                <CheckCircle2 className="h-3 w-3" />
              ) : (
                <XCircle className="h-3 w-3" />
              )}
              {t.name}
              <span className="opacity-60">· {t.category}</span>
            </span>
          ))}
        </div>
      </Card>

      <div className="grid grid-cols-12 gap-4">
        {/* 左栏：目标列表 */}
        <div className="col-span-4">
          <Card title="扫描目标">
            <div className="space-y-1">
              {targets.length === 0 && (
                <p className="py-6 text-center text-sm text-slate-400">
                  暂无目标，点击「新建目标」添加
                </p>
              )}
              {targets.map((t) => (
                <TargetRow
                  key={t.id}
                  target={t}
                  selected={selectedTargetId === t.id}
                  onSelect={() => {
                    setSelectedTargetId(t.id)
                    setSelectedJobId(null)
                  }}
                  onDelete={() => deleteTargetMut.mutate(t.id)}
                />
              ))}
            </div>
          </Card>
        </div>

        {/* 右栏：任务列表 + 详情 */}
        <div className="col-span-8 space-y-4">
          <Card title="扫描任务">
            <div className="space-y-1">
              {jobs.length === 0 && (
                <p className="py-6 text-center text-sm text-slate-400">
                  {selectedTargetId ? '该目标暂无扫描记录' : '选择目标或发起扫描'}
                </p>
              )}
              {jobs.map((j) => (
                <JobRow
                  key={j.id}
                  job={j}
                  selected={selectedJobId === j.id}
                  onSelect={() => setSelectedJobId(j.id)}
                  onCancel={() => cancelJobMut.mutate(j.id)}
                />
              ))}
            </div>
          </Card>

          {selectedJobId && <JobDetail jobId={selectedJobId} />}
        </div>
      </div>

      {/* 新建目标弹层 */}
      {showNewTarget && (
        <NewTargetForm
          onSubmit={(req) => createTargetMut.mutate(req)}
          onCancel={() => setShowNewTarget(false)}
          loading={createTargetMut.isPending}
        />
      )}

      {/* 发起扫描弹层 */}
      {showNewScan && (
        <NewScanForm
          targets={targets}
          availableTools={availableTools}
          onSubmit={(req) => createJobMut.mutate(req)}
          onCancel={() => setShowNewScan(false)}
          loading={createJobMut.isPending}
        />
      )}
    </div>
  )
}

// ==================== 目标行 ====================

function TargetRow({
  target,
  selected,
  onSelect,
  onDelete,
}: {
  target: ScanTarget
  selected: boolean
  onSelect: () => void
  onDelete: () => void
}) {
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
          <span className="font-medium text-slate-700">{target.name}</span>
          <span className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-500">
            {target.target_type}
          </span>
        </div>
        <div className="mt-0.5 truncate text-xs text-slate-400">{target.location}</div>
      </div>
      <button
        onClick={(e) => {
          e.stopPropagation()
          onDelete()
        }}
        className="opacity-0 transition group-hover:opacity-100"
      >
        <Trash2 className="h-4 w-4 text-rose-400 hover:text-rose-600" />
      </button>
    </div>
  )
}

// ==================== 任务行 ====================

function JobRow({
  job,
  selected,
  onSelect,
  onCancel,
}: {
  job: ScanJobSummary
  selected: boolean
  onSelect: () => void
  onCancel: () => void
}) {
  const status = STATUS_STYLE[job.status] || STATUS_STYLE.pending
  const totalFindings =
    job.critical_count + job.high_count + job.medium_count + job.low_count + job.info_count

  return (
    <div
      onClick={onSelect}
      className={cn(
        'group flex cursor-pointer items-center gap-3 rounded-lg border px-3 py-2 text-sm',
        selected ? 'border-brand-300 bg-brand-50' : 'border-transparent hover:bg-slate-50',
      )}
    >
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-slate-500">#{job.id}</span>
          <span
            className={cn('rounded px-1.5 py-0.5 text-xs font-medium', status.badge)}
          >
            {status.label}
          </span>
          {job.status === 'running' && (
            <span className="flex items-center gap-1 text-xs text-blue-600">
              <Loader2 className="h-3 w-3 animate-spin" />
              {job.progress}%
            </span>
          )}
          <span className="text-xs text-slate-400">{job.trigger}</span>
        </div>
        <div className="mt-0.5 flex items-center gap-2 text-xs text-slate-400">
          <span>{formatDateTime(job.created_at)}</span>
          <span>· {job.tools.join(', ') || '无工具'}</span>
        </div>
      </div>

      {/* finding 计数徽章 */}
      {job.status === 'completed' && (
        <div className="flex items-center gap-1">
          {job.critical_count > 0 && (
            <span className="rounded bg-rose-100 px-1.5 py-0.5 text-xs text-rose-700">
              {job.critical_count}C
            </span>
          )}
          {job.high_count > 0 && (
            <span className="rounded bg-orange-100 px-1.5 py-0.5 text-xs text-orange-700">
              {job.high_count}H
            </span>
          )}
          {job.medium_count > 0 && (
            <span className="rounded bg-amber-100 px-1.5 py-0.5 text-xs text-amber-700">
              {job.medium_count}M
            </span>
          )}
          {totalFindings === 0 && (
            <span className="flex items-center gap-1 text-xs text-emerald-600">
              <ShieldCheck className="h-3 w-3" /> 无漏洞
            </span>
          )}
        </div>
      )}

      {(job.status === 'running' || job.status === 'pending') && (
        <button
          onClick={(e) => {
            e.stopPropagation()
            onCancel()
          }}
          className="text-slate-400 hover:text-rose-600"
        >
          <X className="h-4 w-4" />
        </button>
      )}
    </div>
  )
}

// ==================== 任务详情（finding 表格 + 门禁） ====================

function JobDetail({ jobId }: { jobId: number }) {
  const [severityFilter, setSeverityFilter] = useState<string>('')

  const findingsQuery = useQuery({
    queryKey: ['scan-findings', jobId, severityFilter],
    queryFn: () =>
      api.listFindings(jobId, {
        severity: severityFilter || undefined,
      }),
  })

  const gateQuery = useQuery({
    queryKey: ['scan-gate', jobId],
    queryFn: () => api.evaluateGate(jobId),
    enabled: findingsQuery.data?.items !== undefined,
  })

  const findings = findingsQuery.data?.items || []
  const counts = findingsQuery.data?.counts || {}
  const gate = gateQuery.data

  return (
    <Card
      title="漏洞发现"
      subtitle={`任务 #${jobId} · 共 ${findingsQuery.data?.total || 0} 条`}
      actions={
        gate && (
          <span
            className={cn(
              'flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium',
              gate.passed
                ? 'bg-emerald-100 text-emerald-700'
                : 'bg-rose-100 text-rose-700',
            )}
          >
            {gate.passed ? (
              <ShieldCheck className="h-3 w-3" />
            ) : (
              <ShieldAlert className="h-3 w-3" />
            )}
            门禁{gate.passed ? '通过' : '失败'} · {gate.policy_name}
          </span>
        )
      }
    >
      {/* 严重度统计 + 过滤 */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((sev) => {
          const style = SEVERITY_STYLE[sev]
          const count = counts[sev] || 0
          if (count === 0) return null
          return (
            <button
              key={sev}
              onClick={() => setSeverityFilter(severityFilter === sev ? '' : sev)}
              className={cn(
                'rounded-md border px-2 py-0.5 text-xs',
                severityFilter === sev
                  ? style.badge + ' ring-2 ring-offset-1'
                  : style.badge,
              )}
            >
              {style.label} {count}
            </button>
          )
        })}
        {severityFilter && (
          <button
            onClick={() => setSeverityFilter('')}
            className="text-xs text-slate-400 hover:text-slate-600"
          >
            清除过滤
          </button>
        )}
      </div>

      {/* 门禁失败原因 */}
      {gate && !gate.passed && gate.reasons.length > 0 && (
        <div className="mb-3 rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-700">
          <div className="font-medium">门禁失败原因：</div>
          <ul className="mt-1 list-disc pl-4">
            {gate.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}

      {/* finding 表格 */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 text-left text-xs text-slate-400">
              <th className="py-2 pr-2 font-medium">严重度</th>
              <th className="py-2 pr-2 font-medium">工具</th>
              <th className="py-2 pr-2 font-medium">标题</th>
              <th className="py-2 pr-2 font-medium">位置</th>
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 && (
              <tr>
                <td colSpan={4} className="py-6 text-center text-slate-400">
                  无符合条件的漏洞
                </td>
              </tr>
            )}
            {findings.map((f) => (
              <FindingRow key={f.id} finding={f} />
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function FindingRow({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false)
  const style = SEVERITY_STYLE[finding.severity] || SEVERITY_STYLE.info

  return (
    <>
      <tr
        onClick={() => setExpanded(!expanded)}
        className="cursor-pointer border-b border-slate-50 hover:bg-slate-50"
      >
        <td className="py-2 pr-2">
          <span className={cn('rounded border px-1.5 py-0.5 text-xs', style.badge)}>
            {style.label}
          </span>
        </td>
        <td className="py-2 pr-2 text-xs text-slate-500">{finding.tool}</td>
        <td className="py-2 pr-2">
          <div className="truncate text-slate-700" style={{ maxWidth: 300 }}>
            {finding.title || finding.rule_id}
          </div>
        </td>
        <td className="py-2 pr-2 text-xs text-slate-400">
          {finding.file}
          {finding.line > 0 && `:${finding.line}`}
        </td>
      </tr>
      {expanded && (
        <tr className="bg-slate-50">
          <td colSpan={4} className="px-3 py-2 text-xs">
            {finding.cve && (
              <div className="mb-1">
                <span className="font-mono text-rose-600">{finding.cve}</span>
              </div>
            )}
            <div className="whitespace-pre-wrap text-slate-600">{finding.message}</div>
            {finding.fix && (
              <div className="mt-2 rounded bg-emerald-50 px-2 py-1 text-emerald-700">
                修复建议: {finding.fix}
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

// ==================== 新建目标表单 ====================

function NewTargetForm({
  onSubmit,
  onCancel,
  loading,
}: {
  onSubmit: (req: {
    name: string
    target_type: 'git' | 'path' | 'image'
    location: string
    ref?: string
  }) => void
  onCancel: () => void
  loading: boolean
}) {
  const [name, setName] = useState('')
  const [targetType, setTargetType] = useState<'git' | 'path' | 'image'>('git')
  const [location, setLocation] = useState('')
  const [ref, setRef] = useState('main')

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30">
      <Card title="新建扫描目标" className="w-full max-w-md">
        <div className="space-y-3">
          <Field label="名称">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="如：ContentShield 后端"
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            />
          </Field>
          <Field label="类型">
            <select
              value={targetType}
              onChange={(e) => setTargetType(e.target.value as 'git' | 'path' | 'image')}
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            >
              <option value="git">Git 仓库</option>
              <option value="path">本地路径</option>
              <option value="image">容器镜像</option>
            </select>
          </Field>
          <Field label={targetType === 'git' ? '仓库 URL' : targetType === 'image' ? '镜像 tag' : '绝对路径'}>
            <input
              value={location}
              onChange={(e) => setLocation(e.target.value)}
              placeholder={
                targetType === 'git'
                  ? 'https://github.com/user/repo.git'
                  : targetType === 'image'
                    ? 'nginx:1.21'
                    : '/path/to/project'
              }
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            />
          </Field>
          {targetType === 'git' && (
            <Field label="分支/Tag">
              <input
                value={ref}
                onChange={(e) => setRef(e.target.value)}
                className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
              />
            </Field>
          )}
          <div className="flex justify-end gap-2 pt-2">
            <button
              onClick={onCancel}
              className="rounded-lg px-3 py-1.5 text-sm text-slate-500 hover:bg-slate-100"
            >
              取消
            </button>
            <button
              onClick={() => name && location && onSubmit({ name, target_type: targetType, location, ref })}
              disabled={!name || !location || loading}
              className="rounded-lg bg-brand-500 px-3 py-1.5 text-sm text-white hover:bg-brand-600 disabled:opacity-40"
            >
              {loading ? '创建中...' : '创建'}
            </button>
          </div>
        </div>
      </Card>
    </div>
  )
}

// ==================== 发起扫描表单 ====================

function NewScanForm({
  targets,
  availableTools,
  onSubmit,
  onCancel,
  loading,
}: {
  targets: ScanTarget[]
  availableTools: string[]
  onSubmit: (req: { target_id: number; tools: string[] }) => void
  onCancel: () => void
  loading: boolean
}) {
  const [targetId, setTargetId] = useState<number>(targets[0]?.id || 0)
  const [selectedTools, setSelectedTools] = useState<string[]>(
    availableTools.length > 0 ? availableTools.slice(0, 3) : [],
  )

  const toggleTool = (name: string) => {
    setSelectedTools((prev) =>
      prev.includes(name) ? prev.filter((t) => t !== name) : [...prev, name],
    )
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30">
      <Card title="发起扫描" className="w-full max-w-md">
        <div className="space-y-3">
          <Field label="扫描目标">
            <select
              value={targetId}
              onChange={(e) => setTargetId(Number(e.target.value))}
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            >
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.target_type})
                </option>
              ))}
            </select>
          </Field>
          <Field label="扫描工具">
            <div className="space-y-1">
              {availableTools.map((name) => (
                <label key={name} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={selectedTools.includes(name)}
                    onChange={() => toggleTool(name)}
                  />
                  <span>{name}</span>
                </label>
              ))}
              {availableTools.length === 0 && (
                <p className="text-xs text-rose-500">
                  无可用工具，请在 worker 环境安装 bandit/gitleaks/trivy 等
                </p>
              )}
            </div>
          </Field>
          <div className="flex justify-end gap-2 pt-2">
            <button
              onClick={onCancel}
              className="rounded-lg px-3 py-1.5 text-sm text-slate-500 hover:bg-slate-100"
            >
              取消
            </button>
            <button
              onClick={() =>
                targetId && selectedTools.length > 0 && onSubmit({ target_id: targetId, tools: selectedTools })
              }
              disabled={!targetId || selectedTools.length === 0 || loading}
              className="rounded-lg bg-brand-500 px-3 py-1.5 text-sm text-white hover:bg-brand-600 disabled:opacity-40"
            >
              {loading ? '提交中...' : '开始扫描'}
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
