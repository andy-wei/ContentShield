/**
 * 训练数据安全扫描页面。
 *
 * 布局：
 * - 左栏：数据集列表（上传 + 管理）
 * - 右栏：扫描任务列表 + 问题样本表格 + 报告摘要
 */
import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Database,
  Upload,
  Trash2,
  Play,
  Loader2,
  FlaskConical,
  AlertTriangle,
} from 'lucide-react'
import { api } from '../api/client'
import type { Dataset, DatasetScanSummary, DatasetFinding } from '../api/types'
import { Card } from '../components/Card'
import { cn, formatDateTime } from '../lib/format'

const STATUS_STYLE: Record<string, { badge: string; label: string }> = {
  pending: { badge: 'bg-slate-100 text-slate-600', label: '等待' },
  running: { badge: 'bg-blue-100 text-blue-700', label: '运行中' },
  completed: { badge: 'bg-emerald-100 text-emerald-700', label: '完成' },
  failed: { badge: 'bg-rose-100 text-rose-700', label: '失败' },
}

const ISSUE_LABEL: Record<string, string> = {
  pii: 'PII 泄露',
  toxic: '有害内容',
  injection: '注入攻击',
  poison: '投毒嫌疑',
  secret: '密钥泄露',
  other: '其他',
}

export function Training() {
  const qc = useQueryClient()
  const [selectedDatasetId, setSelectedDatasetId] = useState<number | null>(null)
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null)
  const [showUpload, setShowUpload] = useState(false)

  const datasetsQuery = useQuery({
    queryKey: ['datasets'],
    queryFn: api.listDatasets,
  })

  const scansQuery = useQuery({
    queryKey: ['dataset-scans', selectedDatasetId],
    queryFn: () =>
      api.listDatasetScans(
        selectedDatasetId ? { dataset_id: selectedDatasetId } : undefined,
      ),
    refetchInterval: (query) => {
      const scans = query.state.data || []
      return scans.some((s) => s.status === 'running' || s.status === 'pending')
        ? 5000
        : false
    },
  })

  const deleteDatasetMut = useMutation({
    mutationFn: api.deleteDataset,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['datasets'] }),
  })

  const createScanMut = useMutation({
    mutationFn: api.createDatasetScan,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dataset-scans'] }),
  })

  const datasets = datasetsQuery.data || []
  const scans = scansQuery.data || []

  return (
    <div className="space-y-4">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold text-slate-800">
            <FlaskConical className="h-5 w-5 text-brand-500" />
            训练数据安全
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            训练/微调数据集安全扫描 · 复用 6 层检测引擎 + 投毒检测 + 数据溯源
          </p>
        </div>
        <button
          onClick={() => setShowUpload(true)}
          className="flex items-center gap-1 rounded-lg bg-brand-500 px-3 py-1.5 text-sm text-white hover:bg-brand-600"
        >
          <Upload className="h-4 w-4" /> 上传数据集
        </button>
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* 左栏：数据集列表 */}
        <div className="col-span-4">
          <Card title="数据集">
            <div className="space-y-1">
              {datasets.length === 0 && (
                <p className="py-6 text-center text-sm text-slate-400">
                  暂无数据集，点击「上传数据集」
                </p>
              )}
              {datasets.map((d) => (
                <DatasetRow
                  key={d.id}
                  dataset={d}
                  selected={selectedDatasetId === d.id}
                  onSelect={() => {
                    setSelectedDatasetId(d.id)
                    setSelectedScanId(null)
                  }}
                  onDelete={() => deleteDatasetMut.mutate(d.id)}
                />
              ))}
            </div>
          </Card>
        </div>

        {/* 右栏：扫描任务 + 详情 */}
        <div className="col-span-8 space-y-4">
          <Card title="扫描任务">
            <div className="space-y-1">
              {scans.length === 0 && (
                <p className="py-6 text-center text-sm text-slate-400">
                  {selectedDatasetId ? '该数据集暂无扫描记录' : '选择数据集或发起扫描'}
                </p>
              )}
              {scans.map((s) => (
                <ScanRow
                  key={s.id}
                  scan={s}
                  selected={selectedScanId === s.id}
                  onSelect={() => setSelectedScanId(s.id)}
                />
              ))}
            </div>
          </Card>

          {selectedDatasetId && scans.length === 0 && (
            <Card>
              <button
                onClick={() => createScanMut.mutate(selectedDatasetId)}
                disabled={createScanMut.isPending}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-brand-50 py-3 text-sm text-brand-600 hover:bg-brand-100"
              >
                <Play className="h-4 w-4" />
                {createScanMut.isPending ? '提交中...' : '发起首次扫描'}
              </button>
            </Card>
          )}

          {selectedScanId && <ScanDetail scanId={selectedScanId} />}
        </div>
      </div>

      {showUpload && (
        <UploadForm
          onCancel={() => setShowUpload(false)}
          onSuccess={() => {
            setShowUpload(false)
            qc.invalidateQueries({ queryKey: ['datasets'] })
          }}
        />
      )}
    </div>
  )
}

// ==================== 数据集行 ====================

function DatasetRow({
  dataset,
  selected,
  onSelect,
  onDelete,
}: {
  dataset: Dataset
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
          <Database className="h-3.5 w-3.5 text-slate-400" />
          <span className="font-medium text-slate-700">{dataset.name}</span>
          <span className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-500">
            {dataset.format}
          </span>
        </div>
        <div className="mt-0.5 text-xs text-slate-400">
          {dataset.record_count} 条 · {dataset.source}
          {dataset.version && ` · ${dataset.version}`}
        </div>
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

// ==================== 扫描行 ====================

function ScanRow({
  scan,
  selected,
  onSelect,
}: {
  scan: DatasetScanSummary
  selected: boolean
  onSelect: () => void
}) {
  const status = STATUS_STYLE[scan.status] || STATUS_STYLE.pending
  const issueTotal = Object.values(scan.stats).reduce((a, b) => a + b, 0)

  return (
    <div
      onClick={onSelect}
      className={cn(
        'flex cursor-pointer items-center gap-3 rounded-lg border px-3 py-2 text-sm',
        selected ? 'border-brand-300 bg-brand-50' : 'border-transparent hover:bg-slate-50',
      )}
    >
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-slate-500">#{scan.id}</span>
          <span className={cn('rounded px-1.5 py-0.5 text-xs font-medium', status.badge)}>
            {status.label}
          </span>
          {scan.status === 'running' && (
            <span className="flex items-center gap-1 text-xs text-blue-600">
              <Loader2 className="h-3 w-3 animate-spin" />
              {scan.progress}%
            </span>
          )}
        </div>
        <div className="mt-0.5 text-xs text-slate-400">
          扫描 {scan.scanned_count} 条 · 标记 {scan.flagged_count} 条 ·{' '}
          {formatDateTime(scan.created_at)}
        </div>
      </div>
      {scan.status === 'completed' && issueTotal > 0 && (
        <span className="flex items-center gap-1 text-xs text-amber-600">
          <AlertTriangle className="h-3 w-3" />
          {issueTotal} 问题
        </span>
      )}
      {scan.status === 'completed' && issueTotal === 0 && scan.flagged_count === 0 && (
        <span className="text-xs text-emerald-600">无问题</span>
      )}
    </div>
  )
}

// ==================== 扫描详情 ====================

function ScanDetail({ scanId }: { scanId: number }) {
  const [issueFilter, setIssueFilter] = useState<string>('')

  const findingsQuery = useQuery({
    queryKey: ['dataset-findings', scanId, issueFilter],
    queryFn: () =>
      api.listDatasetFindings(scanId, {
        issue_type: issueFilter || undefined,
      }),
  })

  const findings = findingsQuery.data?.items || []
  const issueCounts = findingsQuery.data?.issue_counts || {}

  return (
    <Card
      title="问题样本"
      subtitle={`扫描 #${scanId} · 共 ${findingsQuery.data?.total || 0} 条`}
    >
      {/* 问题类型过滤 */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {Object.entries(issueCounts).map(([type, count]) => (
          <button
            key={type}
            onClick={() => setIssueFilter(issueFilter === type ? '' : type)}
            className={cn(
              'rounded-md border px-2 py-0.5 text-xs',
              issueFilter === type
                ? 'border-rose-300 bg-rose-100 text-rose-700 ring-2 ring-offset-1'
                : 'border-amber-200 bg-amber-50 text-amber-700',
            )}
          >
            {ISSUE_LABEL[type] || type} {count}
          </button>
        ))}
        {issueFilter && (
          <button
            onClick={() => setIssueFilter('')}
            className="text-xs text-slate-400 hover:text-slate-600"
          >
            清除过滤
          </button>
        )}
      </div>

      {/* 问题样本表格 */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 text-left text-xs text-slate-400">
              <th className="py-2 pr-2 font-medium">行号</th>
              <th className="py-2 pr-2 font-medium">问题类型</th>
              <th className="py-2 pr-2 font-medium">风险</th>
              <th className="py-2 pr-2 font-medium">预览</th>
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 && (
              <tr>
                <td colSpan={4} className="py-6 text-center text-slate-400">
                  无符合条件的问题样本
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

function FindingRow({ finding }: { finding: DatasetFinding }) {
  const [expanded, setExpanded] = useState(false)
  const riskColor =
    finding.risk_score >= 0.66
      ? 'text-rose-600'
      : finding.risk_score >= 0.33
        ? 'text-amber-600'
        : 'text-emerald-600'

  return (
    <>
      <tr
        onClick={() => setExpanded(!expanded)}
        className="cursor-pointer border-b border-slate-50 hover:bg-slate-50"
      >
        <td className="py-2 pr-2 font-mono text-xs text-slate-500">{finding.record_idx}</td>
        <td className="py-2 pr-2">
          <div className="flex flex-wrap gap-1">
            {finding.issue_types.map((t) => (
              <span
                key={t}
                className="rounded bg-amber-50 px-1.5 py-0.5 text-xs text-amber-700"
              >
                {ISSUE_LABEL[t] || t}
              </span>
            ))}
            {finding.poison_type && (
              <span className="rounded bg-rose-50 px-1.5 py-0.5 text-xs text-rose-700">
                {finding.poison_type}
              </span>
            )}
          </div>
        </td>
        <td className={cn('py-2 pr-2 text-xs font-medium', riskColor)}>
          {(finding.risk_score * 100).toFixed(0)}%
        </td>
        <td className="py-2 pr-2">
          <div className="truncate text-xs text-slate-500" style={{ maxWidth: 250 }}>
            {finding.preview}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr className="bg-slate-50">
          <td colSpan={4} className="px-3 py-2 text-xs">
            <div className="mb-1 text-slate-400">
              哈希: <span className="font-mono">{finding.record_hash}</span>
            </div>
            <div className="mb-1">
              决策: <span className="font-medium">{finding.decision}</span> · 类别:{' '}
              {finding.categories.join(', ') || '无'}
            </div>
            <div className="whitespace-pre-wrap text-slate-600">{finding.preview}</div>
          </td>
        </tr>
      )}
    </>
  )
}

// ==================== 上传表单 ====================

function UploadForm({
  onCancel,
  onSuccess,
}: {
  onCancel: () => void
  onSuccess: () => void
}) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [name, setName] = useState('')
  const [format, setFormat] = useState<'jsonl' | 'csv' | 'txt'>('jsonl')
  const [source, setSource] = useState('internal')
  const [version, setVersion] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)

  const submit = async () => {
    if (!name || !file) return
    setLoading(true)
    try {
      await api.uploadDataset({ name, format, source, version, file })
      onSuccess()
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30">
      <Card title="上传数据集" className="w-full max-w-md">
        <div className="space-y-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-600">名称</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="如：SFT 训练集 v1"
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-600">格式</label>
              <select
                value={format}
                onChange={(e) => setFormat(e.target.value as 'jsonl' | 'csv' | 'txt')}
                className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
              >
                <option value="jsonl">JSONL</option>
                <option value="csv">CSV</option>
                <option value="txt">TXT</option>
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-600">来源</label>
              <input
                value={source}
                onChange={(e) => setSource(e.target.value)}
                className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
              />
            </div>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-600">版本（可选）</label>
            <input
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              placeholder="如 v1.0"
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-600">文件</label>
            <input
              ref={fileRef}
              type="file"
              accept=".jsonl,.csv,.txt"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="w-full text-sm"
            />
            {file && (
              <p className="mt-1 text-xs text-slate-400">
                {file.name} ({(file.size / 1024).toFixed(1)} KB)
              </p>
            )}
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
              disabled={!name || !file || loading}
              className="rounded-lg bg-brand-500 px-3 py-1.5 text-sm text-white hover:bg-brand-600 disabled:opacity-40"
            >
              {loading ? '上传中...' : '上传'}
            </button>
          </div>
        </div>
      </Card>
    </div>
  )
}
