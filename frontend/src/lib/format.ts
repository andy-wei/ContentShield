/** 工具函数。 */
import { clsx, type ClassValue } from 'clsx'
import type { Decision } from '../api/types'

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs)
}

/** 决策对应的颜色与文案。 */
export const decisionStyle: Record<
  Decision | 'skipped',
  { label: string; badge: string; text: string; dot: string }
> = {
  block: {
    label: '拦截',
    badge: 'bg-rose-100 text-rose-700 border-rose-200',
    text: 'text-rose-600',
    dot: 'bg-rose-500',
  },
  warn: {
    label: '警告',
    badge: 'bg-amber-100 text-amber-700 border-amber-200',
    text: 'text-amber-600',
    dot: 'bg-amber-500',
  },
  pass: {
    label: '通过',
    badge: 'bg-emerald-100 text-emerald-700 border-emerald-200',
    text: 'text-emerald-600',
    dot: 'bg-emerald-500',
  },
  skipped: {
    label: '跳过',
    badge: 'bg-slate-100 text-slate-500 border-slate-200',
    text: 'text-slate-400',
    dot: 'bg-slate-300',
  },
}

/** 层级中文名。 */
export const layerLabel: Record<string, string> = {
  lexicon: 'L0 词库',
  prompt_guard: 'L1 注入检测',
  llama_guard: 'L2 危害分类',
  dlp: 'L3 DLP 防泄露',
  indirect_injection: 'L1.5 间接注入',
  cross_verify: 'L4 交叉验证',
}

/** 风险评分颜色。 */
export function riskColor(score: number): string {
  if (score >= 0.66) return 'text-rose-600'
  if (score >= 0.33) return 'text-amber-600'
  return 'text-emerald-600'
}

/** 格式化日期时间。 */
export function formatDateTime(iso: string): string {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
    d.getHours(),
  )}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

/** 数字千分位。 */
export function formatNumber(n: number): string {
  return n.toLocaleString('en-US')
}
