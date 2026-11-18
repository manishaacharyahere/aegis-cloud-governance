import { useCallback, useEffect, useRef, useState } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { Check, Copy, X } from 'lucide-react'
import { cn } from '@/lib/utils'

/*
 * Copies a value and confirms with an icon swap. Adapted from SmoothUI's
 * ButtonCopy (MIT, https://smoothui.dev): idle -> success icons cross-fade
 * with a short blur; the request counter ignores stale clicks.
 */
export function CopyButton({ value, label = 'Copy', className }: { value: string; label?: string; className?: string }) {
  const [state, setState] = useState<'idle' | 'success' | 'error'>('idle')
  const reduce = useReducedMotion()
  const request = useRef(0)
  const timer = useRef<number | undefined>(undefined)
  useEffect(() => () => window.clearTimeout(timer.current), [])

  const copy = useCallback(async () => {
    const id = ++request.current
    try {
      await navigator.clipboard.writeText(value)
      if (id === request.current) setState('success')
    } catch {
      if (id === request.current) setState('error')
    }
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setState('idle'), 1600)
  }, [value])

  const icon = state === 'success' ? <Check /> : state === 'error' ? <X /> : <Copy />
  return (
    <button type="button" onClick={copy} aria-label={state === 'success' ? 'Copied' : state === 'error' ? 'Copy failed' : label}
      className={cn('inline-flex size-6 shrink-0 items-center justify-center overflow-hidden rounded text-fg-subtle transition-colors hover:bg-surface-3 hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring [&_svg]:size-3.5',
        state === 'success' && 'text-success', state === 'error' && 'text-danger', className)}>
      <AnimatePresence initial={false} mode="popLayout">
        <motion.span key={state} className="flex"
          initial={reduce ? { opacity: 1 } : { opacity: 0, y: -8, filter: 'blur(4px)' }}
          animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
          exit={reduce ? { opacity: 0, transition: { duration: 0 } } : { opacity: 0, y: 8, filter: 'blur(4px)' }}
          transition={{ type: 'spring', bounce: 0, duration: 0.25 }}>
          {icon}
        </motion.span>
      </AnimatePresence>
    </button>
  )
}

/** An identifier: monospace, truncated with the full value in a tooltip, with a copy button. */
export function Mono({ value, copy = true, className, max = 48 }: { value: string; copy?: boolean; className?: string; max?: number }) {
  const shown = value.length > max ? value.slice(0, max - 1) + '…' : value
  return (
    <span className={cn('inline-flex max-w-full items-center gap-1 align-middle', className)}>
      <code className="mono truncate font-mono text-[12.5px]" title={value}>{shown}</code>
      {copy && <CopyButton value={value} label={`Copy ${value}`} />}
    </span>
  )
}
