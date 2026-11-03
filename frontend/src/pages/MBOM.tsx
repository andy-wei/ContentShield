/**
 * 模型供应链安全（MBOM）页面。
 *
 * 布局：
 * - 顶部：风险摘要（总数、各风险等级数、未签名、未校验）
 * - 制品表格：名称、类型、来源、license、完整性、签名、风险
 * - 选中制品后展示详情 + 风险评估
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Package,
  Plus,
  Trash2,
  ShieldCheck,
  ShieldAlert,
  Loader2,
  Download,
} from 'lucide-react'
import { api } from '../api/client'
import type { ModelArtifactSummary } from '../api/types'
import { Card } from '../components/Card'
import { cn } from '../lib/format'

const RISK_STYLE: Record<string, { badge: string; label: string }> = {
  low: { badge: 'bg-emerald-100 text-emerald-700', label: '低风险' },
  medium: { badge: 'bg-amber-100 text-amber-700', label: '中风险' },
  high: { badge: 'bg-orange-100 text-orange-700', label: '高风险' },
  critical: { badge: 'bg-rose-100 text-rose-700', label: '严重' },
}

const INTEGRITY_STYLE: Record<string, { badge: string; label: string }> = {
  unknown: { badge: 'bg-slate-100 text-slate-500', label: '未校验' },
  verified: { badge: 'bg-emerald-100 text-emerald-700', label: '已验证' },
  tampered: { badge: 'bg-rose-100 text-rose-700', label: '已篡改' },
}

const SIGNATURE_STYLE: Record<string, { badge: string; label: string }> = {
  unsigned: { badge: 'bg-slate-100 text-slate-500', label: '未签名' },
  signed: { badge: 'bg-blue-100 text-blue-700', label: '已签名' },
  verified: { badge: 'bg-emerald-100 text-emerald-700', label: '已验证' },
  failed: { badge: 'bg-rose-100 text-rose-700', label: '验证失败' },
}

export function MBOM() {
  const qc = useQueryClient()
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [showCreate, setShowCreate] = useState(false)

  const exportQuery = useQuery({
    queryKey: ['mbom-export'],
    queryFn: api.exportMBOM,
  })

  const artifactsQuery = useQuery({
    queryKey: ['mbom-artifacts'],
    queryFn: () => api.listArtifacts(),
  })

  const deleteMut = useMutation({
    mutationFn: api.deleteArtifact,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mbom-artifacts'] }),
  })

  const summary = exportQuery.data?.risk_summary || {}
  const artifacts = artifactsQuery.data || []

  return (
    <div className="space-y-4">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold text-slate-800">
            <Package className="h-5 w-5 text-brand-500" />
            模型供应链
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            模型物料清单（MBOM）· 哈希完整性校验 · License 合规 · 供应链风险评估
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => exportQuery.refetch()}
            className="flex items-center gap-1 rounded-lg border border-slate-200 px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-50"
          >
            <Download className="h-4 w-4" /> 导出 MBOM
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1 rounded-lg bg-brand-500 px-3 py-1.5 text-sm text-white hover:bg-brand-600"
          >
            <Plus className="h-4 w-4" /> 登记模型
          </button>
        </div>
      </div>

      {/* 风险摘要 */}
      <div className="grid grid-cols-6 gap-3">
        <RiskCard label="模型总数" value={summary.total || 0} color="text-slate-700" />
        <RiskCard label="低风险" value={summary.low || 0} color="text-emerald-600" />
        <RiskCard label="中风险" value={summary.medium || 0} color="text-amber-600" />
        <RiskCard label="高风险" value={summary.high || 0} color="text-orange-600" />
        <RiskCard label="未签名" value={summary.unsigned || 0} color="text-slate-500" />
        <RiskCard
          label="未校验完整性"
          value={summary.unverified_integrity || 0}
          color="text-rose-600"
        />
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* 左栏：制品表格 */}
        <div className="col-span-7">
          <Card title="模型制品">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 text-left text-xs text-slate-400">
                    <th className="py-2 pr-2 font-medium">名称</th>
                    <th className="py-2 pr-2 font-medium">来源</th>
                    <th className="py-2 pr-2 font-medium">License</th>
                    <th className="py-2 pr-2 font-medium">完整性</th>
                  </tr>
                </thead>
                <tbody>
                  {artifacts.length === 0 && (
                    <tr>
                      <td colSpan={4} className="py-6 text-center text-slate-400">
                        暂无模型制品，点击「登记模型」
                      </td>
                    </tr>
                  )}
                  {artifacts.map((a) => (
                    <ArtifactRow
                      key={a.id}
                      artifact={a}
                      selected={selectedId === a.id}
                      onSelect={() => setSelectedId(a.id)}
                      onDelete={() => deleteMut.mutate(a.id)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>

        {/* 右栏：详情 + 风险 */}
        <div className="col-span-5">
          {selectedId ? (
            <ArtifactDetail artifactId={selectedId} />
          ) : (
            <Card>
              <p className="py-12 text-center text-sm text-slate-400">
                选择模型查看详情与风险评估
              </p>
            </Card>
          )}
        </div>
      </div>

      {showCreate && (
        <CreateArtifactForm
          onCancel={() => setShowCreate(false)}
          onSuccess={() => {
            setShowCreate(false)
            qc.invalidateQueries({ queryKey: ['mbom-artifacts'] })
            qc.invalidateQueries({ queryKey: ['mbom-export'] })
          }}
        />
      )}
    </div>
  )
}

function RiskCard({
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

// ==================== 制品行 ====================

function ArtifactRow({
  artifact,
  selected,
  onSelect,
  onDelete,
}: {
  artifact: ModelArtifactSummary
  selected: boolean
  onSelect: () => void
  onDelete: () => void
}) {
  const integrity = INTEGRITY_STYLE[artifact.integrity_status] || INTEGRITY_STYLE.unknown

  return (
    <tr
      onClick={onSelect}
      className={cn(
        'group cursor-pointer border-b border-slate-50 hover:bg-slate-50',
        selected && 'bg-brand-50',
      )}
    >
      <td className="py-2 pr-2">
        <div className="font-medium text-slate-700">{artifact.name}</div>
        <div className="text-xs text-slate-400">
          {artifact.model_type} · v{artifact.version || '-'}
        </div>
      </td>
      <td className="py-2 pr-2 text-xs text-slate-500">{artifact.source}</td>
      <td className="py-2 pr-2 text-xs text-slate-500">{artifact.license}</td>
      <td className="py-2 pr-2">
        <div className="flex items-center gap-2">
          <span className={cn('rounded px-1.5 py-0.5 text-xs', integrity.badge)}>
            {integrity.label}
          </span>
          <button
            onClick={(e) => {
              e.stopPropagation()
              onDelete()
            }}
            className="opacity-0 transition group-hover:opacity-100"
          >
            <Trash2 className="h-3.5 w-3.5 text-rose-400 hover:text-rose-600" />
          </button>
        </div>
      </td>
    </tr>
  )
}

// ==================== 制品详情 + 风险 ====================

function ArtifactDetail({ artifactId }: { artifactId: number }) {
  const artifactQuery = useQuery({
    queryKey: ['mbom-artifact', artifactId],
    queryFn: () => api.getArtifact(artifactId),
  })
  const riskQuery = useQuery({
    queryKey: ['mbom-risk', artifactId],
    queryFn: () => api.getArtifactRisk(artifactId),
  })
  const verifyMut = useMutation({
    mutationFn: api.verifyArtifact,
    onSuccess: () => {
      riskQuery.refetch()
      artifactQuery.refetch()
    },
  })

  if (artifactQuery.isLoading) {
    return (
      <Card>
        <div className="flex items-center justify-center py-12 text-slate-400">
          <Loader2 className="mr-2 h-5 w-5 animate-spin" /> 加载...
        </div>
      </Card>
    )
  }

  const artifact = artifactQuery.data
  const risk = riskQuery.data
  if (!artifact) return null

  const riskStyle = risk ? RISK_STYLE[risk.risk_level] : null
  const integrity = INTEGRITY_STYLE[artifact.integrity_status]
  const signature = SIGNATURE_STYLE[artifact.signature_status]

  return (
    <div className="space-y-3">
      <Card title={artifact.name} subtitle={`${artifact.model_type} · ${artifact.source}`}>
        <div className="space-y-2 text-sm">
          <InfoRow label="来源标识" value={artifact.source_id || '-'} />
          <InfoRow label="版本" value={artifact.version || '-'} />
          <InfoRow
            label="大小"
            value={artifact.size_bytes ? `${(artifact.size_bytes / 1024 / 1024).toFixed(1)} MB` : '-'}
          />
          <InfoRow label="License" value={artifact.license} />
          <div className="flex items-center gap-2">
            <span className={cn('rounded px-1.5 py-0.5 text-xs', integrity.badge)}>
              {integrity.label}
            </span>
            <span className={cn('rounded px-1.5 py-0.5 text-xs', signature.badge)}>
              {signature.label}
            </span>
            {riskStyle && (
              <span className={cn('rounded px-1.5 py-0.5 text-xs font-medium', riskStyle.badge)}>
                {riskStyle.label} ({risk?.risk_score})
              </span>
            )}
          </div>
        </div>

        {artifact.sha256 && (
          <div className="mt-3 rounded bg-slate-50 p-2">
            <div className="mb-1 text-xs text-slate-400">SHA256</div>
            <div className="break-all font-mono text-xs text-slate-600">
              {artifact.sha256}
            </div>
          </div>
        )}

        <div className="mt-3 flex gap-2">
          <button
            onClick={() => verifyMut.mutate(artifactId)}
            disabled={verifyMut.isPending}
            className="flex items-center gap-1 rounded-lg bg-brand-50 px-3 py-1.5 text-xs text-brand-600 hover:bg-brand-100 disabled:opacity-40"
          >
            {verifyMut.isPending ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <ShieldCheck className="h-3 w-3" />
            )}
            校验完整性
          </button>
        </div>

        {verifyMut.data && (
          <div
            className={cn(
              'mt-2 rounded-md px-3 py-2 text-xs',
              verifyMut.data.verified
                ? 'bg-emerald-50 text-emerald-700'
                : 'bg-rose-50 text-rose-700',
            )}
          >
            {verifyMut.data.message}
          </div>
        )}
      </Card>

      {/* 风险评估 */}
      {risk && (
        <Card title="供应链风险评估">
          <div className="space-y-3">
            <div>
              <div className="mb-1 text-xs font-medium text-slate-500">风险项</div>
              <ul className="space-y-1">
                {risk.issues.map((issue, i) => (
                  <li key={i} className="flex items-start gap-1 text-xs text-slate-600">
                    <ShieldAlert className="mt-0.5 h-3 w-3 flex-shrink-0 text-amber-500" />
                    <span>{issue}</span>
                  </li>
                ))}
              </ul>
            </div>
            {risk.recommendations.length > 0 && (
              <div>
                <div className="mb-1 text-xs font-medium text-slate-500">建议</div>
                <ul className="space-y-1">
                  {risk.recommendations.map((rec, i) => (
                    <li key={i} className="flex items-start gap-1 text-xs text-emerald-700">
                      <span className="text-emerald-500">→</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  )
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-slate-400">{label}</span>
      <span className="font-medium text-slate-700">{value}</span>
    </div>
  )
}

// ==================== 登记模型表单 ====================

function CreateArtifactForm({
  onCancel,
  onSuccess,
}: {
  onCancel: () => void
  onSuccess: () => void
}) {
  const [name, setName] = useState('')
  const [modelType, setModelType] = useState('base')
  const [source, setSource] = useState('huggingface')
  const [sourceId, setSourceId] = useState('')
  const [version, setVersion] = useState('')
  const [filePath, setFilePath] = useState('')
  const [license, setLicense] = useState('unknown')
  const [loading, setLoading] = useState(false)

  const submit = async () => {
    if (!name) return
    setLoading(true)
    try {
      await api.createArtifact({
        name,
        model_type: modelType as 'base' | 'fine_tuned' | 'lora_adapter' | 'embedding' | 'guard',
        source: source as 'huggingface' | 'internal' | 'openai' | 'anthropic' | 'custom',
        source_id: sourceId,
        version,
        file_path: filePath,
        license,
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
      <Card title="登记模型制品" className="max-h-[90vh] w-full max-w-md overflow-y-auto">
        <div className="space-y-3">
          <Field label="名称">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="如：Llama-Guard-4-12B"
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="类型">
              <select
                value={modelType}
                onChange={(e) => setModelType(e.target.value)}
                className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
              >
                <option value="base">Base 基座</option>
                <option value="fine_tuned">微调</option>
                <option value="lora_adapter">LoRA</option>
                <option value="embedding">Embedding</option>
                <option value="guard">安全防护</option>
              </select>
            </Field>
            <Field label="来源">
              <select
                value={source}
                onChange={(e) => setSource(e.target.value)}
                className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
              >
                <option value="huggingface">HuggingFace</option>
                <option value="internal">内部</option>
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic</option>
                <option value="custom">自定义</option>
              </select>
            </Field>
          </div>
          <Field label="来源标识（HF repo id / 路径 / API model）">
            <input
              value={sourceId}
              onChange={(e) => setSourceId(e.target.value)}
              placeholder="如：meta-llama/LlamaGuard-4-12B"
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="版本">
              <input
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
              />
            </Field>
            <Field label="License">
              <input
                value={license}
                onChange={(e) => setLicense(e.target.value)}
                placeholder="apache-2.0"
                className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
              />
            </Field>
          </div>
          <Field label="文件路径（可选，相对 data_dir）">
            <input
              value={filePath}
              onChange={(e) => setFilePath(e.target.value)}
              placeholder="如：models/llama-guard-4-12b.gguf"
              className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm"
            />
          </Field>
          <div className="flex justify-end gap-2 pt-2">
            <button
              onClick={onCancel}
              className="rounded-lg px-3 py-1.5 text-sm text-slate-500 hover:bg-slate-100"
            >
              取消
            </button>
            <button
              onClick={submit}
              disabled={!name || loading}
              className="rounded-lg bg-brand-500 px-3 py-1.5 text-sm text-white hover:bg-brand-600 disabled:opacity-40"
            >
              {loading ? '登记中...' : '登记'}
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
