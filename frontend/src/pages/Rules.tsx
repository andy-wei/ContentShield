/** 策略配置：类别开关、词库管理、DLP 规则管理。 */
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2 } from 'lucide-react'
import { api } from '../api/client'
import { Card } from '../components/Card'
import { cn } from '../lib/format'

export function Rules() {
  const [tab, setTab] = useState<'categories' | 'lexicon' | 'dlp'>('categories')
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-800">策略配置</h1>
        <p className="mt-1 text-sm text-slate-500">管理检测类别、敏感词库、DLP 正则规则</p>
      </div>

      <div className="flex gap-1 border-b border-slate-200">
        {(
          [
            ['categories', '危害类别 (S1-S14)'],
            ['lexicon', '敏感词库'],
            ['dlp', 'DLP 正则规则'],
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={cn(
              'border-b-2 px-4 py-2 text-sm font-medium transition-colors',
              tab === key
                ? 'border-brand-500 text-brand-600'
                : 'border-transparent text-slate-500 hover:text-slate-700',
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'categories' && <CategoriesPanel />}
      {tab === 'lexicon' && <LexiconPanel />}
      {tab === 'dlp' && <DlpPanel />}
    </div>
  )
}

function CategoriesPanel() {
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['categories'],
    queryFn: api.listCategories,
  })
  const updateMut = useMutation({
    mutationFn: (v: { code: string; body: Record<string, unknown> }) =>
      api.updateCategory(v.code, v.body as never),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['categories'] }),
  })

  return (
    <Card title="Llama-Guard-4 危害类别" subtitle="勾选启用的类别；处置：拦截 / 警告 / 关闭">
      <div className="space-y-2">
        {data?.map((c) => (
          <div
            key={c.code}
            className="flex items-center gap-3 rounded-lg border border-slate-200 p-3"
          >
            <input
              type="checkbox"
              checked={c.enabled}
              onChange={(e) =>
                updateMut.mutate({ code: c.code, body: { enabled: e.target.checked } })
              }
              className="h-4 w-4 accent-brand-500"
            />
            <span className="w-10 rounded bg-slate-100 px-1.5 py-0.5 text-center text-xs font-mono font-medium text-slate-600">
              {c.code}
            </span>
            <div className="flex-1">
              <div className="text-sm text-slate-800">{c.name}</div>
            </div>
            <select
              value={c.action}
              onChange={(e) =>
                updateMut.mutate({ code: c.code, body: { action: e.target.value } })
              }
              className="rounded-md border border-slate-200 px-2 py-1 text-xs"
            >
              <option value="block">拦截</option>
              <option value="warn">警告</option>
              <option value="off">关闭</option>
            </select>
          </div>
        ))}
      </div>
    </Card>
  )
}

function LexiconPanel() {
  const qc = useQueryClient()
  const [term, setTerm] = useState('')
  const [category, setCategory] = useState('profanity')
  const [lang, setLang] = useState<'zh' | 'en'>('zh')

  const { data } = useQuery({
    queryKey: ['lexicon'],
    queryFn: () => api.listLexicon(),
  })
  const addMut = useMutation({
    mutationFn: () =>
      api.addLexicon({ term, category, lang, action: lang === 'zh' ? 'warn' : 'warn' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['lexicon'] })
      setTerm('')
    },
  })
  const delMut = useMutation({
    mutationFn: (id: number) => api.deleteLexicon(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['lexicon'] }),
  })

  return (
    <Card
      title="敏感词库"
      subtitle="脏话 / 辱骂 / 色情 / 暴力关键词（L0 层快速命中）"
    >
      <div className="mb-4 flex gap-2">
        <input
          value={term}
          onChange={(e) => setTerm(e.target.value)}
          placeholder="输入敏感词..."
          className="flex-1 rounded-md border border-slate-200 px-3 py-1.5 text-sm"
          onKeyDown={(e) => e.key === 'Enter' && term && addMut.mutate()}
        />
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="rounded-md border border-slate-200 px-2 py-1.5 text-sm"
        >
          <option value="profanity">脏话</option>
          <option value="abuse">辱骂</option>
          <option value="sexual">色情</option>
          <option value="violence">暴力</option>
        </select>
        <select
          value={lang}
          onChange={(e) => setLang(e.target.value as 'zh' | 'en')}
          className="rounded-md border border-slate-200 px-2 py-1.5 text-sm"
        >
          <option value="zh">中文</option>
          <option value="en">英文</option>
        </select>
        <button
          onClick={() => term && addMut.mutate()}
          className="inline-flex items-center gap-1 rounded-md bg-brand-500 px-3 py-1.5 text-sm text-white hover:bg-brand-600"
        >
          <Plus size={14} /> 添加
        </button>
      </div>

      <div className="max-h-96 space-y-1 overflow-auto">
        {data?.map((e) => (
          <div
            key={e.id}
            className="flex items-center justify-between rounded border border-slate-100 px-3 py-1.5 text-sm"
          >
            <span className="font-medium text-slate-700">{e.term}</span>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span>{e.lang === 'zh' ? '中文' : '英文'}</span>
              <span className="rounded bg-slate-100 px-1.5 py-0.5">{e.category}</span>
              <button
                onClick={() => delMut.mutate(e.id)}
                className="text-slate-400 hover:text-rose-500"
              >
                <Trash2 size={13} />
              </button>
            </div>
          </div>
        ))}
        {data?.length === 0 && (
          <div className="py-8 text-center text-sm text-slate-400">暂无词库条目</div>
        )}
      </div>
    </Card>
  )
}

function DlpPanel() {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [pattern, setPattern] = useState('')
  const [cat, setCat] = useState('secret')

  const { data } = useQuery({
    queryKey: ['dlp'],
    queryFn: api.listDlp,
  })
  const addMut = useMutation({
    mutationFn: () =>
      api.addDlp({ name, pattern, category: cat, action: 'block', weight: 0.8 }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dlp'] })
      setName('')
      setPattern('')
    },
  })
  const delMut = useMutation({
    mutationFn: (id: number) => api.deleteDlp(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dlp'] }),
  })

  return (
    <Card
      title="DLP 正则规则"
      subtitle="密钥 / 凭证 / PII 泄露检测（L3 层正则匹配）"
    >
      <div className="mb-4 grid grid-cols-1 gap-2 md:grid-cols-[1fr_1fr_auto_auto]">
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="规则名称"
          className="rounded-md border border-slate-200 px-3 py-1.5 text-sm"
        />
        <input
          value={pattern}
          onChange={(e) => setPattern(e.target.value)}
          placeholder="正则表达式"
          className="rounded-md border border-slate-200 px-3 py-1.5 text-sm font-mono"
        />
        <select
          value={cat}
          onChange={(e) => setCat(e.target.value)}
          className="rounded-md border border-slate-200 px-2 py-1.5 text-sm"
        >
          <option value="secret">密钥</option>
          <option value="credential">凭证</option>
          <option value="pii">个人隐私</option>
        </select>
        <button
          onClick={() => name && pattern && addMut.mutate()}
          className="inline-flex items-center gap-1 rounded-md bg-brand-500 px-3 py-1.5 text-sm text-white hover:bg-brand-600"
        >
          <Plus size={14} /> 添加
        </button>
      </div>

      <div className="space-y-1">
        {data?.map((r) => (
          <div
            key={r.id}
            className="flex items-center justify-between rounded border border-slate-100 px-3 py-1.5"
          >
            <div className="min-w-0 flex-1">
              <span className="text-sm font-medium text-slate-700">{r.name}</span>
              <code className="ml-2 truncate text-xs text-slate-400">{r.pattern}</code>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="rounded bg-slate-100 px-1.5 py-0.5">{r.category}</span>
              <button
                onClick={() => delMut.mutate(r.id)}
                className="text-slate-400 hover:text-rose-500"
              >
                <Trash2 size={13} />
              </button>
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}
