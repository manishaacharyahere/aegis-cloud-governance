import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { AlertOctagon, CheckCircle2, X } from 'lucide-react'
import { OVERLAY_INITIAL, spring } from '@/lib/motion'
import { cn } from '@/lib/utils'

type Toast = { id: number; text: string; tone: 'ok' | 'bad' }
type Push = (text: string, tone?: 'ok' | 'bad') => void
const ToastContext = createContext<Push>(() => {})

/** Provides useToast(). Successes are polite status messages; errors are alerts. */
export function Toaster({ children }: { children: ReactNode }) {
  const [list, setList] = useState<Toast[]>([])
  const dismiss = useCallback((id: number) => setList((l) => l.filter((t) => t.id !== id)), [])
  const push = useCallback<Push>((text, tone = 'ok') => {
    const id = Date.now() + Math.random()
    setList((l) => [...l.slice(-3), { id, text, tone }])
    window.setTimeout(() => dismiss(id), tone === 'bad' ? 8000 : 5000)
  }, [dismiss])
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-[min(380px,calc(100vw-32px))] flex-col gap-2">
        <AnimatePresence initial={false}>
          {list.map((t) => (
            <motion.div key={t.id} layout initial={OVERLAY_INITIAL} animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.97, transition: { duration: 0.12 } }} transition={spring.slow}
              role={t.tone === 'bad' ? 'alert' : 'status'}
              className={cn('toast pointer-events-auto flex items-start gap-2.5 rounded-lg border bg-surface px-3.5 py-3 text-[13px] shadow-card',
                t.tone === 'bad' ? 'border-danger/40' : 'border-success/40')}>
              {t.tone === 'bad' ? <AlertOctagon className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden /> : <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" aria-hidden />}
              <span className="min-w-0 flex-1">{t.text}</span>
              <button type="button" onClick={() => dismiss(t.id)} aria-label="Dismiss" className="text-fg-subtle hover:text-fg"><X className="size-3.5" /></button>
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
