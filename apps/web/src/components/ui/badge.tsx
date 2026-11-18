import type { ReactNode } from 'react'
import { AlertOctagon, AlertTriangle, CheckCircle2, CircleDashed, Info, Loader2, ShieldAlert } from 'lucide-react'
import { cn } from '@/lib/utils'
import { humanize, toneClasses, toneOf, type Tone } from '@/lib/tones'

const ICONS: Record<Tone, ReactNode> = {
  danger: <AlertOctagon />,
  high: <ShieldAlert />,
  warning: <AlertTriangle />,
  success: <CheckCircle2 />,
  info: <Info />,
  accent: <Loader2 className="animate-spin motion-reduce:animate-none" />,
  neutral: <CircleDashed />,
}

/**
 * A status or severity chip. The tone comes from the value (toneOf), and an
 * icon accompanies the colour so the meaning never depends on colour alone.
 */
export function StatusBadge({ value, label, icon = true, className }: {
  value: string
  label?: ReactNode
  icon?: boolean
  className?: string
}) {
  const tone = toneOf(value)
  return (
    <span className={cn('badge inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-[11.5px] font-medium leading-4',
      toneClasses[tone], className)}>
      {icon && <span className="[&_svg]:size-3" aria-hidden>{ICONS[tone]}</span>}
      {label ?? humanize(value)}
    </span>
  )
}

/** A neutral or toned chip for non-status labels (counts, tags). */
export function Chip({ children, tone = 'neutral', className }: { children: ReactNode; tone?: Tone; className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11.5px] font-medium leading-4', toneClasses[tone], className)}>
      {children}
    </span>
  )
}
