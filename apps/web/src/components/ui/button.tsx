import { forwardRef, type ButtonHTMLAttributes } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { LoaderCircle } from 'lucide-react'
import { cn } from '@/lib/utils'

const buttonVariants = cva(
  'inline-flex shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-md border text-sm font-medium ' +
    'transition-[background-color,border-color,color,box-shadow,transform] duration-150 ease-out ' +
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ' +
    'active:scale-[0.97] motion-reduce:active:scale-100 disabled:pointer-events-none disabled:opacity-50 ' +
    '[&_svg]:size-4 [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        primary: 'border-transparent bg-accent text-accent-fg shadow-sm hover:bg-accent/90',
        secondary: 'border-border bg-surface-2 text-fg hover:border-border-strong hover:bg-surface-3',
        ghost: 'border-transparent bg-transparent text-fg-muted hover:bg-surface-2 hover:text-fg',
        danger: 'border-danger/40 bg-danger/10 text-danger hover:bg-danger/20',
        link: 'h-auto border-transparent bg-transparent p-0 text-accent underline-offset-4 hover:underline active:scale-100',
      },
      size: {
        sm: 'h-7 px-2.5 text-xs',
        md: 'h-8 px-3',
        lg: 'h-10 px-4',
        icon: 'size-8 p-0',
      },
    },
    defaultVariants: { variant: 'secondary', size: 'md' },
  },
)

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> {
  /** Shows a spinner and disables the button while an action runs. */
  loading?: boolean
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant, size, loading, disabled, children, type = 'button', ...props },
  ref,
) {
  return (
    <button ref={ref} type={type} className={cn(buttonVariants({ variant, size }), className)}
      disabled={disabled || loading} aria-busy={loading || undefined} {...props}>
      {loading && <LoaderCircle className="animate-spin motion-reduce:animate-none" aria-hidden />}
      {children}
    </button>
  )
})

// eslint-disable-next-line react-refresh/only-export-components
export { buttonVariants }
