/** 身份管理页：NHI 创建/列表/轮转/禁用 + Token 管理 + OAuth 测试。 */
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  Copy,
  Check,
  KeyRound,
  Plus,
  RefreshCw,
  Trash2,
  LogIn,
  ShieldCheck,
} from 'lucide-react'
import { api } from '../api/client'
import { Card } from '../components/Card'
import { cn } from '../lib/format'
import { useAuth } from '../store/auth'
import type { NhiPrincipal } from '../api/types'

export function Identities() {
  const [showCreate, setShowCreate] = useState(false)
  const [createdSecret, setCreatedSecret] = useState<{
    clientId: string
    secret: string
  } | null>(null)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-800">身份与凭据管理</h1>
        <p className="mt-1 text-sm text-slate-500">
          非人类身份（NHI）颁发 · OAuth 2.0 动态令牌 · 凭据保险库
        </p>
      </div>

      {/* 安全提示 */}
      <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3">
        <AlertTriangle size={16} className="mt-0.5 flex-shrink-0 text-amber-500" />
        <div className="text-xs text-amber-700">
          <strong>安全设计：</strong>client_secret 和上游凭据经 Fernet 加密存储，明文仅创建/轮转时返回一次。
          access_token 默认 15 分钟过期，支持即时撤销（黑名单）。每个 NHI 可绑定独立的上游凭据。
        </div>
      </div>

      {/* 已创建的 secret 一次性展示 */}
      {createdSecret && (
        <Card title="🎉 NHI 创建成功 — 请立即保存凭据（仅此一次显示）">
          <div className="space-y-3">
            <SecretField label="client_id" value={createdSecret.clientId} />
            <SecretField label="client_secret" value={createdSecret.secret} highlight />
            <div className="text-xs text-rose-500">
              ⚠️ secret 关闭此页后将无法再次查看，请妥善保存。
            </div>
            <button
              onClick={() => {
                setCreatedSecret(null)
                setShowCreate(false)
              }}
              className="rounded-md bg-brand-500 px-4 py-1.5 text-sm text-white hover:bg-brand-600"
            >
              我已保存
            </button>
          </div>
        </Card>
      )}

      {/* 创建表单 */}
      {showCreate && !createdSecret && (
        <CreatePrincipalForm
          onCreated={(clientId, secret) => {
            setCreatedSecret({ clientId, secret })
            setShowCreate(false)
          }}
          onCancel={() => setShowCreate(false)}
        />
      )}

      {/* NHI 列表 */}
      <PrincipalsList onCreate={() => setShowCreate(true)} />

      {/* Token 测试工具 */}
      <TokenTester />
    </div>
  )
}

function SecretField({
  label,
  value,
  highlight,
}: {
  label: string
  value: string
  highlight?: boolean
}) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <div>
      <div className="mb-1 text-xs text-slate-500">{label}</div>
      <div className="flex items-center gap-2">
        <code
          className={cn(
            'flex-1 truncate rounded-md border px-3 py-2 font-mono text-sm',
            highlight ? 'border-rose-200 bg-rose-50 text-rose-700' : 'border-slate-200 bg-slate-50',
          )}
        >
          {value}
        </code>
        <button
          onClick={copy}
          className="rounded-md border border-slate-200 p-2 text-slate-500 hover:bg-slate-50"
        >
          {copied ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
        </button>
      </div>
    </div>
  )
}

function CreatePrincipalForm({
  onCreated,
  onCancel,
}: {
  onCreated: (clientId: string, secret: string) => void
  onCancel: () => void
}) {
  const qc = useQueryClient()
  const [label, setLabel] = useState('')
  const [type, setType] = useState('agent')
  const [provider, setProvider] = useState('')
  const [upstreamKey, setUpstreamKey] = useState('')
  const [upstreamUrl, setUpstreamUrl] = useState('')

  const mut = useMutation({
    mutationFn: () =>
      api.createPrincipal({
        label,
        principal_type: type,
        upstream_provider: provider || undefined,
        upstream_api_key: upstreamKey || undefined,
        upstream_base_url: upstreamUrl || undefined,
      }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['principals'] })
      onCreated(r.client_id, r.client_secret)
    },
  })

  return (
    <Card title="创建非人类身份（NHI）">
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <div>
          <label className="mb-1 block text-xs text-slate-500">名称 *</label>
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="如：客服 Agent"
            className="w-full rounded-md border border-slate-200 px-3 py-1.5 text-sm"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-500">类型</label>
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="w-full rounded-md border border-slate-200 px-3 py-1.5 text-sm"
          >
            <option value="agent">agent</option>
            <option value="service">service</option>
            <option value="mcp_server">mcp_server</option>
          </select>
        </div>
      </div>
      <div className="mt-3 border-t border-slate-100 pt-3">
        <div className="mb-2 text-xs font-medium text-slate-600">
          上游凭据（可选，为空则用全局配置）
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <input
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            placeholder="provider (openai/azure)"
            className="rounded-md border border-slate-200 px-3 py-1.5 text-sm"
          />
          <input
            value={upstreamKey}
            onChange={(e) => setUpstreamKey(e.target.value)}
            placeholder="上游 API Key"
            className="rounded-md border border-slate-200 px-3 py-1.5 text-sm"
          />
          <input
            value={upstreamUrl}
            onChange={(e) => setUpstreamUrl(e.target.value)}
            placeholder="上游 Base URL"
            className="rounded-md border border-slate-200 px-3 py-1.5 text-sm"
          />
        </div>
      </div>
      <div className="mt-4 flex gap-2">
        <button
          onClick={() => label && mut.mutate()}
          disabled={!label || mut.isPending}
          className="inline-flex items-center gap-1 rounded-md bg-brand-500 px-4 py-1.5 text-sm text-white hover:bg-brand-600 disabled:opacity-50"
        >
          <Plus size={14} /> 创建
        </button>
        <button
          onClick={onCancel}
          className="rounded-md border border-slate-200 px-4 py-1.5 text-sm text-slate-600 hover:bg-slate-50"
        >
          取消
        </button>
      </div>
    </Card>
  )
}

function PrincipalsList({ onCreate }: { onCreate: () => void }) {
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['principals'],
    queryFn: api.listPrincipals,
  })

  const [rotated, setRotated] = useState<{ id: number; secret: string } | null>(null)

  const delMut = useMutation({
    mutationFn: (id: number) => api.deletePrincipal(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['principals'] }),
  })
  const rotMut = useMutation({
    mutationFn: (id: number) => api.rotateSecret(id),
    onSuccess: (r) => setRotated({ id: r.id, secret: r.client_secret }),
  })

  return (
    <Card
      title="已颁发的非人类身份"
      actions={
        <button
          onClick={onCreate}
          className="inline-flex items-center gap-1 rounded-md bg-brand-500 px-3 py-1 text-xs text-white hover:bg-brand-600"
        >
          <KeyRound size={13} /> 颁发 NHI
        </button>
      }
    >
      {rotated && (
        <div className="mb-3 rounded-md border border-rose-200 bg-rose-50 p-3">
          <div className="mb-1 text-xs font-medium text-rose-700">
            ✅ Secret 已轮转（NHI #{rotated.id}）— 新 secret 仅此一次显示：
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 truncate font-mono text-sm text-rose-700">
              {rotated.secret}
            </code>
            <button
              onClick={() => navigator.clipboard.writeText(rotated.secret)}
              className="text-rose-400 hover:text-rose-600"
            >
              <Copy size={14} />
            </button>
            <button
              onClick={() => setRotated(null)}
              className="text-xs text-rose-400 hover:text-rose-600"
            >
              关闭
            </button>
          </div>
        </div>
      )}

      <div className="space-y-2">
        {data?.length === 0 && (
          <div className="py-8 text-center text-sm text-slate-400">暂无 NHI，点击「颁发 NHI」创建</div>
        )}
        {data?.map((p: NhiPrincipal) => (
          <div
            key={p.id}
            className={cn(
              'flex items-center gap-3 rounded-lg border p-3',
              p.enabled ? 'border-slate-200' : 'border-slate-200 bg-slate-50 opacity-60',
            )}
          >
            <div className={cn('flex h-8 w-8 items-center justify-center rounded-full',
              p.enabled ? 'bg-brand-50 text-brand-500' : 'bg-slate-200 text-slate-400')}>
              <ShieldCheck size={16} />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-slate-800">{p.label}</span>
                <span className={cn(
                  'rounded px-1.5 py-0.5 text-[10px]',
                  p.enabled ? 'bg-emerald-100 text-emerald-600' : 'bg-slate-200 text-slate-500',
                )}>
                  {p.enabled ? '启用' : '已禁用'}
                </span>
              </div>
              <div className="mt-0.5 truncate font-mono text-xs text-slate-400">
                {p.client_id}
                {p.upstream_provider && (
                  <span className="ml-2 text-slate-500">→ {p.upstream_provider}</span>
                )}
              </div>
            </div>
            <button
              onClick={() => rotMut.mutate(p.id)}
              disabled={!p.enabled}
              title="轮转 secret"
              className="rounded p-1.5 text-slate-400 hover:bg-amber-50 hover:text-amber-500 disabled:opacity-30"
            >
              <RefreshCw size={14} />
            </button>
            <button
              onClick={() => delMut.mutate(p.id)}
              title="禁用"
              className="rounded p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-500"
            >
              <Trash2 size={14} />
            </button>
          </div>
        ))}
      </div>
    </Card>
  )
}

function TokenTester() {
  const { token, clientId, setToken, clear } = useAuth()
  const [cid, setCid] = useState('')
  const [secret, setSecret] = useState('')
  const [error, setError] = useState('')

  const mut = useMutation({
    mutationFn: () => api.getToken(cid, secret),
    onSuccess: (r) => {
      setToken(r.access_token, cid)
      setError('')
      setSecret('')
    },
    onError: (e: unknown) => {
      setError(e instanceof Error ? e.message : '获取 token 失败')
    },
  })

  return (
    <Card title="OAuth 2.0 Token 测试" subtitle="用 client_id + secret 换取 access_token，测试 /v1/* 端点鉴权">
      {token ? (
        <div className="space-y-3">
          <div className="flex items-center gap-2 rounded-md bg-emerald-50 px-3 py-2 text-sm text-emerald-700">
            <Check size={16} />
            已认证：<code className="font-mono text-xs">{clientId}</code>
          </div>
          <div className="text-xs text-slate-500">
            access_token: <code className="font-mono">{token.slice(0, 40)}...</code>
          </div>
          <button
            onClick={() => {
              clear()
              setCid('')
            }}
            className="rounded-md border border-slate-200 px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-50"
          >
            登出（清除 token）
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs text-slate-500">client_id</label>
              <input
                value={cid}
                onChange={(e) => setCid(e.target.value)}
                placeholder="agent-xxxx"
                className="w-full rounded-md border border-slate-200 px-3 py-1.5 text-sm font-mono"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-slate-500">client_secret</label>
              <input
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                type="password"
                placeholder="••••••"
                className="w-full rounded-md border border-slate-200 px-3 py-1.5 text-sm font-mono"
              />
            </div>
          </div>
          {error && <div className="text-xs text-rose-500">{error}</div>}
          <button
            onClick={() => cid && secret && mut.mutate()}
            disabled={!cid || !secret || mut.isPending}
            className="inline-flex items-center gap-1 rounded-md bg-brand-500 px-4 py-1.5 text-sm text-white hover:bg-brand-600 disabled:opacity-50"
          >
            <LogIn size={14} /> 获取 Token
          </button>
        </div>
      )}
    </Card>
  )
}
