/** 系统设置：推理后端状态、健康检查、隐私说明。 */
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, XCircle, AlertTriangle, RefreshCw, Zap, Loader2 } from 'lucide-react'
import { api } from '../api/client'
import { Card } from '../components/Card'
import { useSettings } from '../store/settings'
import { cn } from '../lib/format'

const PROFILE_DESC: Record<string, string> = {
  cloud: 'Llama-Guard-4 走云 API（OpenRouter/NVIDIA/Together），无需 GPU，秒级响应。',
  'local-gpu': '本地 vLLM 服务，需要 NVIDIA GPU（FP16 约 24GB+ VRAM，AWQ 约 8-10GB）。',
  'local-cpu': '本地 llama.cpp GGUF（INT4 量化），纯 CPU，单次数秒~数十秒，仅演示/离线。',
}

export function Settings() {
  const { health, loading, refreshHealth } = useSettings()
  const { data: detailedHealth } = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
    refetchInterval: 30000,
  })

  const profile = health?.inference_profile ?? '-'
  const backends = detailedHealth?.backends ?? {}

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-800">系统设置</h1>
        <p className="mt-1 text-sm text-slate-500">推理后端状态、健康检查与隐私说明</p>
      </div>

      {/* 当前 profile */}
      <Card
        title="推理后端"
        subtitle="通过 .env 的 INFERENCE_PROFILE 切换，重启 backend 容器生效"
        actions={
          <button
            onClick={refreshHealth}
            disabled={loading}
            className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1 text-xs hover:bg-slate-50"
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> 刷新
          </button>
        }
      >
        <div className="mb-3 inline-flex rounded-lg bg-brand-50 px-3 py-1.5 text-sm font-medium text-brand-700">
          当前：{profile}
        </div>
        <p className="text-sm text-slate-600">{PROFILE_DESC[profile] ?? ''}</p>
        <div className="mt-3 rounded-md bg-slate-50 p-3 text-xs text-slate-500">
          切换方式：编辑 <code className="text-brand-600">.env</code> 中{' '}
          <code className="text-brand-600">INFERENCE_PROFILE=cloud|local-gpu|local-cpu</code>
          ，然后 <code>docker compose restart backend</code>。
        </div>
      </Card>

      {/* 健康状态 */}
      <Card title="服务健康状态" subtitle="各模型后端可达性">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <BackendHealth
            name="Llama-Guard-4-12B"
            desc="危害分类（L2 核心层）"
            status={backends?.llama_guard}
          />
          <BackendHealth
            name="Prompt Guard 2 86M"
            desc="注入/越狱检测（L1）"
            status={backends?.prompt_guard}
          />
        </div>
      </Card>

      {/* L4 交叉验证配置 */}
      <CrossVerifyConfigCard />

      {/* 隐私说明 */}
      <Card title="⚠️ 隐私与数据安全说明" actions={null}>
        <div className="space-y-3 text-sm text-slate-600">
          <div className="flex gap-2">
            <AlertTriangle size={16} className="mt-0.5 flex-shrink-0 text-amber-500" />
            <p>
              <strong className="text-amber-700">cloud profile</strong> 会将
              <strong>待检测文本</strong>发送至云厂商（OpenRouter/NVIDIA/Together）进行
              Llama-Guard-4 推理。请勿在含高度敏感数据的场景使用此 profile。
            </p>
          </div>
          <div className="flex gap-2">
            <CheckCircle2 size={16} className="mt-0.5 flex-shrink-0 text-emerald-500" />
            <p>
              数据敏感场景请使用 <strong className="text-emerald-700">local-gpu</strong> 或
              <strong className="text-emerald-700"> local-cpu</strong>，文本不出本机。
            </p>
          </div>
          <div className="flex gap-2">
            <CheckCircle2 size={16} className="mt-0.5 flex-shrink-0 text-emerald-500" />
            <p>
              审计库默认对命中的 PII 片段打码（
              <code>AUDIT_REDACT_PII=true</code>），避免敏感信息二次泄露。
            </p>
          </div>
        </div>
      </Card>
    </div>
  )
}

function BackendHealth({
  name,
  desc,
  status,
}: {
  name: string
  desc: string
  status?: Record<string, unknown>
}) {
  const st = (status?.status as string) ?? 'unknown'
  const ok = st === 'ok'
  return (
    <div className="rounded-lg border border-slate-200 p-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-medium text-slate-800">{name}</div>
          <div className="text-xs text-slate-500">{desc}</div>
        </div>
        <div
          className={cn(
            'flex h-8 w-8 items-center justify-center rounded-full',
            ok ? 'bg-emerald-50 text-emerald-500' : 'bg-rose-50 text-rose-500',
          )}
        >
          {ok ? <CheckCircle2 size={18} /> : <XCircle size={18} />}
        </div>
      </div>
      <div className="mt-2 text-xs text-slate-400">
        {status?.endpoint ? (
          <div>endpoint: {String(status.endpoint)}</div>
        ) : null}
        {status?.error ? (
          <div className="text-rose-500">error: {String(status.error)}</div>
        ) : null}
        {!status && <div>加载中...</div>}
      </div>
    </div>
  )
}

function CrossVerifyConfigCard() {
  const qc = useQueryClient()
  const [enabled, setEnabled] = useState(false)
  const [baseUrl, setBaseUrl] = useState('https://api.openai.com/v1')
  const [apiKey, setApiKey] = useState('')
  const [model, setModel] = useState('gpt-4o-mini')
  const [testResult, setTestResult] = useState<{ success: boolean; detail: string } | null>(null)

  const { data: config, isLoading } = useQuery({
    queryKey: ['cross-verify-config'],
    queryFn: async () => {
      const r = await api.getCrossVerifyConfig()
      setEnabled(r.enabled)
      setBaseUrl(r.base_url)
      setModel(r.model)
      return r
    },
  })

  const saveMut = useMutation({
    mutationFn: () =>
      api.updateCrossVerifyConfig({ enabled, base_url: baseUrl, api_key: apiKey, model }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cross-verify-config'] })
      setApiKey('') // 保存后清空输入（不再覆盖）
    },
  })

  const testMut = useMutation({
    mutationFn: () =>
      api.testCrossVerify({ enabled, base_url: baseUrl, api_key: apiKey, model }),
    onSuccess: (r) => setTestResult({ success: r.success, detail: r.detail }),
    onError: (e: unknown) =>
      setTestResult({ success: false, detail: e instanceof Error ? e.message : '测试失败' }),
  })

  if (isLoading) return <Card title="L4 交叉验证配置"><div className="text-sm text-slate-400">加载中...</div></Card>

  return (
    <Card
      title="L4 交叉验证配置"
      subtitle="用通用大模型（OpenAI Compatible）补 Llama-Guard-4 盲区，检测 HAP/恶意代码/越狱。命中给 warn（补充意见）"
    >
      <div className="space-y-4">
        {/* 启用开关 */}
        <div className="flex items-center justify-between rounded-lg border border-slate-200 p-3">
          <div>
            <div className="text-sm font-medium text-slate-800">启用 L4 交叉验证</div>
            <div className="text-xs text-slate-500">
              {config?.api_key_set
                ? `已配置 API Key（${config.api_key_masked}）`
                : '⚠️ 尚未配置 API Key'}
            </div>
          </div>
          <button
            onClick={() => setEnabled(!enabled)}
            className={cn(
              'relative h-6 w-11 rounded-full transition-colors',
              enabled ? 'bg-brand-500' : 'bg-slate-300',
            )}
          >
            <span
              className={cn(
                'absolute top-0.5 h-5 w-5 rounded-full bg-white transition-transform',
                enabled ? 'translate-x-5' : 'translate-x-0.5',
              )}
            />
          </button>
        </div>

        {/* 配置表单 */}
        <div className="grid grid-cols-1 gap-3">
          <div>
            <label className="mb-1 block text-xs text-slate-500">Base URL（OpenAI 兼容端点）</label>
            <input
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://api.openai.com/v1"
              className="w-full rounded-md border border-slate-200 px-3 py-1.5 text-sm"
            />
          </div>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs text-slate-500">
                API Key{config?.api_key_set && <span className="text-slate-400">（留空=保留已有）</span>}
              </label>
              <input
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                type="password"
                placeholder={config?.api_key_set ? '••••（已设置）' : 'sk-xxx'}
                className="w-full rounded-md border border-slate-200 px-3 py-1.5 text-sm font-mono"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-slate-500">模型名称</label>
              <input
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder="gpt-4o-mini"
                className="w-full rounded-md border border-slate-200 px-3 py-1.5 text-sm font-mono"
              />
            </div>
          </div>
          <div className="text-xs text-slate-400">
            支持任何 OpenAI Compatible 模型：GPT-4o / Claude / DeepSeek / 本地 vLLM / Ollama 等
          </div>
        </div>

        {/* 测试结果 */}
        {testResult && (
          <div
            className={cn(
              'flex items-start gap-2 rounded-md p-3 text-xs',
              testResult.success ? 'bg-emerald-50 text-emerald-700' : 'bg-rose-50 text-rose-700',
            )}
          >
            {testResult.success ? (
              <CheckCircle2 size={14} className="mt-0.5 flex-shrink-0" />
            ) : (
              <XCircle size={14} className="mt-0.5 flex-shrink-0" />
            )}
            <span>{testResult.detail}</span>
          </div>
        )}

        {/* 操作按钮 */}
        <div className="flex gap-2">
          <button
            onClick={() => testMut.mutate()}
            disabled={testMut.isPending || !baseUrl}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 px-4 py-1.5 text-sm text-slate-600 hover:bg-slate-50 disabled:opacity-50"
          >
            {testMut.isPending ? <Loader2 size={14} className="animate-spin" /> : <Zap size={14} />}
            测试连接
          </button>
          <button
            onClick={() => saveMut.mutate()}
            disabled={saveMut.isPending}
            className="inline-flex items-center gap-1.5 rounded-md bg-brand-500 px-4 py-1.5 text-sm text-white hover:bg-brand-600 disabled:opacity-50"
          >
            {saveMut.isPending ? <Loader2 size={14} className="animate-spin" /> : <CheckCircle2 size={14} />}
            保存配置
          </button>
          {saveMut.isSuccess && (
            <span className="self-center text-xs text-emerald-600">✓ 已保存，配置立即生效</span>
          )}
        </div>
      </div>
    </Card>
  )
}
