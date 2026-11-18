import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { motion } from 'motion/react'
import { OVERLAY_ENTER, OVERLAY_INITIAL, spring } from '@/lib/motion'
import { Button, type ButtonProps } from './button'
import { Field, Textarea } from './field'

/**
 * A button that confirms an irreversible action in a modal dialog. The
 * native <dialog> gives focus trapping, Escape to cancel, an inert page
 * behind it and focus returned to the button afterwards.
 */
export function ConfirmAction({ label, title, description, confirmLabel, tone = 'danger', icon, requireComment, onConfirm, disabled, size, variant }: {
  label: string
  title: string
  description?: ReactNode
  confirmLabel?: string
  tone?: 'danger' | 'primary'
  icon?: ReactNode
  /** Ask for a comment; it is passed to onConfirm. */
  requireComment?: { label: string; minLength?: number }
  onConfirm: (comment: string) => void | Promise<unknown>
  disabled?: boolean
  size?: ButtonProps['size']
  variant?: ButtonProps['variant']
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const [open, setOpen] = useState(false)
  const [comment, setComment] = useState('')
  const [busy, setBusy] = useState(false)
  const titleId = useId()

  useEffect(() => {
    const d = ref.current
    if (!d) return
    if (open && !d.open) d.showModal()
    if (!open && d.open) d.close()
  }, [open])

  const tooShort = requireComment ? comment.trim().length < (requireComment.minLength ?? 1) : false
  const confirm = async () => {
    setBusy(true)
    try {
      await onConfirm(comment.trim())
    } finally {
      setBusy(false)
      setOpen(false)
      setComment('')
    }
  }

  return (
    <>
      <Button variant={variant ?? (tone === 'danger' ? 'danger' : 'primary')} size={size} disabled={disabled} onClick={() => setOpen(true)}>
        {icon}{label}
      </Button>
      <dialog ref={ref} aria-labelledby={titleId} onClose={() => setOpen(false)}
        className="m-auto w-[min(440px,calc(100vw-32px))] rounded-lg border border-border bg-surface p-0 text-fg shadow-2xl">
        {open && (
          <motion.div initial={OVERLAY_INITIAL} animate={OVERLAY_ENTER} transition={spring.slow} className="p-5">
            <h2 id={titleId} className="m-0 text-base font-semibold">{title}</h2>
            {description && <div className="mt-1.5 text-[13px] text-fg-muted">{description}</div>}
            {requireComment && (
              <Field label={requireComment.label} className="mt-4" required>
                {(p) => <Textarea {...p} value={comment} onChange={(e) => setComment(e.target.value)} autoFocus />}
              </Field>
            )}
            <div className="mt-5 flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setOpen(false)} autoFocus={!requireComment}>Cancel</Button>
              <Button variant={tone === 'danger' ? 'danger' : 'primary'} loading={busy} disabled={tooShort} onClick={confirm}>
                {confirmLabel ?? `Yes, ${label.toLowerCase()}`}
              </Button>
            </div>
          </motion.div>
        )}
      </dialog>
    </>
  )
}
