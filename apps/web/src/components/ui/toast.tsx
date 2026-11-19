import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { AlertOctagon, CheckCircle2, X } from 'lucide-react'
import { OVERLAY_INITIAL, spring } from '@/lib/motion'
import { cn } from '@/lib/utils'

type Toast = { id: number; text: string; tone: 'ok' | 'bad' }
type Push = (text: string, tone?: 'ok' | 'bad') => void
const ToastContext = createContext<Push>(() => {})

const lifetime = (tone: Toast['tone']) => (tone === 'bad' ? 8000 : 5000)

/** Provides useToast(). Messages are announced through two live regions that
 * exist from the start (screen readers often miss a region that appears
 * together with its text): successes politely, errors as alerts. A toast stays
 * while the pointer or focus is on it. */
export function Toaster({ children }: { children: ReactNode }) {
  const [list, setList] = useState<Toast[]>([])
  const [said, setSaid] = useState<{ ok: string; bad: string }>({ ok: '', bad: '' })
  const timers = useRef(new Map<number, number>())
  const dismiss = useCallback((id: number) => {
    window.clearTimeout(timers.current.get(id))
    timers.current.delete(id)
    setList((l) => l.filter((t) => t.id !== id))
  }, [])
  const arm = useCallback((t: Toast) => {
    window.clearTimeout(timers.current.get(t.id))
    timers.current.set(t.id, window.setTimeout(() => dismiss(t.id), lifetime(t.tone)))
  }, [dismiss])
  const hold = (id: number) => window.clearTimeout(timers.current.get(id))
  const push = useCallback<Push>((text, tone = 'ok') => {
    const t = { id: Date.now() + Math.random(), text, tone }
    setList((l) => [...l.slice(-3), t])
    setSaid((s) => ({ ...s, [tone]: text }))
    arm(t)
  }, [arm])
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="sr-only" aria-live="polite" aria-atomic="true">{said.ok}</div>
      <div className="sr-only" role="alert" aria-atomic="true">{said.bad}</div>
      <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-[min(380px,calc(100vw-32px))] flex-col gap-2">
        <AnimatePresence initial={false}>
          {list.map((t) => (
            <motion.div key={t.id} layout initial={OVERLAY_INITIAL} animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.97, transition: { duration: 0.12 } }} transition={spring.slow}
              onMouseEnter={() => hold(t.id)} onMouseLeave={() => arm(t)} onFocus={() => hold(t.id)} onBlur={() => arm(t)}
              className={cn('toast pointer-events-auto flex items-start gap-2.5 rounded-lg border bg-surface px-3.5 py-3 text-[13px] shadow-card',
                t.tone === 'bad' ? 'border-danger/40' : 'border-success/40')}>
              {t.tone === 'bad' ? <AlertOctagon className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden /> : <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" aria-hidden />}
              <span className="min-w-0 flex-1">{t.text}</span>
              <button type="button" onClick={() => dismiss(t.id)} aria-label="Dismiss" className="rounded-sm text-fg-subtle hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"><X className="size-3.5" /></button>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export function useToast() {
  return useContext(ToastContext)
}
