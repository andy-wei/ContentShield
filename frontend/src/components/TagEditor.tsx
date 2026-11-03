/** Chip 式标签编辑器：用于工具白名单/黑名单等字符串列表的编辑。 */
import { useState } from 'react'
import { Plus, X } from 'lucide-react'
import { cn } from '../lib/format'

export function TagEditor({
  tags,
  onChange,
  placeholder = '输入后回车添加',
  readOnly = false,
  tone = 'slate',
  emptyHint,
}: {
  tags: string[]
  onChange?: (tags: string[]) => void
  placeholder?: string
  readOnly?: boolean
  /** chip 配色：slate=中性（白名单）、rose=危险（黑名单） */
  tone?: 'slate' | 'rose'
  /** 空列表提示文案 */
  emptyHint?: string
}) {
  const [input, setInput] = useState('')

  const add = () => {
    const t = input.trim()
    if (!t || !onChange) return
    if (tags.includes(t)) {
      setInput('')
      return
    }
    onChange([...tags, t])
    setInput('')
  }

  const remove = (t: string) => {
    onChange?.(tags.filter((x) => x !== t))
  }

  const chipCls =
    tone === 'rose'
      ? 'border-rose-200 bg-rose-50 text-rose-700'
      : 'border-slate-200 bg-slate-50 text-slate-700'

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1.5">
        {tags.length === 0 && emptyHint && (
          <span className="text-xs italic text-slate-400">{emptyHint}</span>
        )}
        {tags.map((t) => (
          <span
            key={t}
            className={cn(
              'inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-xs',
              chipCls,
            )}
          >
            {t}
            {!readOnly && (
              <button
                onClick={() => remove(t)}
                title={`移除 ${t}`}
                className="text-slate-400 hover:text-rose-500"
              >
                <X size={11} />
              </button>
            )}
          </span>
        ))}
      </div>
      {!readOnly && (
        <div className="flex gap-1.5">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault()
                add()
              }
            }}
            placeholder={placeholder}
            className="flex-1 rounded-md border border-slate-200 px-2.5 py-1 font-mono text-xs"
          />
          <button
            onClick={add}
            disabled={!input.trim()}
            className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1 text-xs text-slate-600 hover:bg-slate-50 disabled:opacity-40"
          >
            <Plus size={12} /> 添加
          </button>
        </div>
      )}
    </div>
  )
}
