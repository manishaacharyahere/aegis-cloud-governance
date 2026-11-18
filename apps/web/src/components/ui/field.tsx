import { forwardRef, useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'

const control =
  'w-full rounded-md border border-border bg-surface-2 px-2.5 text-[13px] text-fg placeholder:text-fg-subtle ' +
  'transition-[border-color,box-shadow] duration-150 hover:border-border-strong ' +
  'focus-visible:border-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ' +
  'disabled:cursor-not-allowed disabled:opacity-50 aria-[invalid=true]:border-danger'

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...props }, ref) {
  return <input ref={ref} className={cn(control, 'h-8', props.type === 'file' && 'h-auto py-1.5 file:mr-3 file:rounded file:border-0 file:bg-surface-3 file:px-2.5 file:py-1 file:text-fg', className)} {...props} />
})

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(function Textarea({ className, ...props }, ref) {
  return <textarea ref={ref} className={cn(control, 'min-h-20 py-2', className)} {...props} />
})

/** A native select (keyboard and screen-reader behaviour for free), styled. */
export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select({ className, children, ...props }, ref) {
  return (
    <span className={cn('relative inline-flex min-w-0', className)}>
      <select ref={ref} className={cn(control, 'h-8 appearance-none pr-8')} {...props}>{children}</select>
      <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 size-3.5 -translate-y-1/2 text-fg-subtle" aria-hidden />
    </span>
  )
})

/**
 * A labelled form field. The render prop receives the id and aria props to
 * spread on the control, so label, hint and error are always connected.
 */
export function Field({ label, hint, error, required, className, children }: {
  label: ReactNode
  hint?: ReactNode
  error?: ReactNode
  required?: boolean
  className?: string
  children: (p: { id: string; 'aria-describedby'?: string; 'aria-invalid'?: boolean; required?: boolean }) => ReactNode
}) {
  const id = useId()
  const hintId = hint ? `${id}-hint` : undefined
  const errId = error ? `${id}-err` : undefined
  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      <label htmlFor={id} className="text-[12.5px] font-medium text-fg-muted">
        {label}{required && <span className="text-danger" aria-hidden> *</span>}
      </label>
      {children({ id, 'aria-describedby': [hintId, errId].filter(Boolean).join(' ') || undefined, 'aria-invalid': error ? true : undefined, required })}
      {hint && !error && <p id={hintId} className="m-0 text-xs text-fg-subtle">{hint}</p>}
      {error && <p id={errId} className="m-0 text-xs text-danger">{error}</p>}
    </div>
  )
}

/** Radio options inside a fieldset with a legend (one named group). */
export function RadioGroup<T extends string>({ legend, name, value, onChange, options, className }: {
  legend: ReactNode
  name: string
  value: T
  onChange: (v: T) => void
  options: { value: T; label: ReactNode; hint?: ReactNode }[]
  className?: string
}) {
  return (
    <fieldset className={cn('m-0 min-w-0 border-0 p-0', className)}>
      <legend className="mb-1.5 p-0 text-[12.5px] font-medium text-fg-muted">{legend}</legend>
      <div className="flex flex-wrap gap-2">
        {options.map((o) => (
          <label key={o.value} className={cn('flex cursor-pointer items-start gap-2 rounded-md border px-3 py-2 text-[13px] transition-colors',
            value === o.value ? 'border-accent/60 bg-accent-soft' : 'border-border bg-surface-2 hover:border-border-strong')}>
            <input type="radio" name={name} value={o.value} checked={value === o.value} onChange={() => onChange(o.value)}
              className="mt-0.5 accent-[var(--accent)]" />
            <span>{o.label}{o.hint && <span className="block text-xs text-fg-subtle">{o.hint}</span>}</span>
          </label>
        ))}
      </div>
    </fieldset>
  )
}
