import type { HTMLAttributes, ReactNode } from 'react'
import { cn } from '@/lib/utils'

/** A surface with an optional header (title, description, actions). Cards are never nested. */
export function Card({ title, description, actions, icon, children, className, bodyClassName, ...props }: {
  title?: ReactNode
  description?: ReactNode
  actions?: ReactNode
  icon?: ReactNode
  bodyClassName?: string
} & Omit<HTMLAttributes<HTMLElement>, 'title'>) {
  return (
    <section className={cn('panel min-w-0 rounded-lg border border-border bg-surface shadow-card', className)} {...props}>
      {(title || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-5 py-3.5">
          <div className="flex min-w-0 items-start gap-2.5">
            {icon && <span className="mt-0.5 text-fg-subtle [&_svg]:size-4" aria-hidden>{icon}</span>}
            <div className="min-w-0">
              {title && <h2 className="text-[15px] font-semibold leading-6 tracking-tight">{title}</h2>}
              {description && <p className="mt-0.5 text-[13px] text-fg-muted">{description}</p>}
            </div>
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cn('px-5 py-4', bodyClassName)}>{children}</div>
    </section>
  )
}

/** Label/value pairs for detail views. */
export function KeyValue({ items, className }: { items: { label: ReactNode; value: ReactNode }[]; className?: string }) {
  return (
    <dl className={cn('grid grid-cols-[minmax(110px,auto)_1fr] gap-x-4 gap-y-2 text-[13px]', className)}>
      {items.map((it, i) => (
        <div key={i} className="contents">
          <dt className="text-fg-subtle">{it.label}</dt>
          <dd className="m-0 min-w-0 break-words">{it.value}</dd>
        </div>
      ))}
    </dl>
  )
}
