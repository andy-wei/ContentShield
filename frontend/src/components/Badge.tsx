/** 决策徽章。 */
import type { Decision } from '../api/types'
import { cn, decisionStyle } from '../lib/format'

export function DecisionBadge({
  decision,
  className,
}: {
  decision: Decision | 'skipped'
  className?: string
}) {
  const s = decisionStyle[decision] ?? decisionStyle.pass
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium',
        s.badge,
        className,
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', s.dot)} />
      {s.label}
    </span>
  )
}
