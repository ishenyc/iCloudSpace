import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import { LoaderCircle } from 'lucide-react'
import { cn } from '@/lib/utils'

const buttonVariants = cva('inline-flex shrink-0 items-center justify-center gap-2 rounded-lg text-[13px] font-medium whitespace-nowrap transition-[background-color,border-color,color,box-shadow,transform] duration-150 outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/25 disabled:pointer-events-none disabled:opacity-45 aria-invalid:border-destructive aria-invalid:ring-destructive/20 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*="size-"])]:size-4', {
  variants: {
    variant: {
      default: 'border border-transparent bg-primary text-primary-foreground shadow-xs hover:bg-primary/90 active:translate-y-px',
      primary: 'border border-transparent bg-primary text-primary-foreground shadow-xs hover:bg-primary/90 active:translate-y-px',
      secondary: 'border border-input/45 bg-secondary text-secondary-foreground shadow-xs hover:bg-accent active:translate-y-px',
      outline: 'border border-input/70 bg-secondary/45 text-foreground shadow-xs hover:border-input hover:bg-accent active:translate-y-px',
      ghost: 'hover:bg-accent hover:text-accent-foreground dark:hover:bg-accent/50',
      destructive: 'bg-destructive text-white hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:bg-destructive/60 dark:focus-visible:ring-destructive/40',
      link: 'text-primary underline-offset-4 hover:underline',
    },
    size: {
      default: 'h-9 px-4 py-2 has-[>svg]:px-3',
      xs: 'h-6 gap-1 rounded-md px-2 text-xs has-[>svg]:px-1.5 [&_svg:not([class*="size-"])]:size-3',
      sm: 'h-8 gap-1.5 rounded-md px-3 has-[>svg]:px-2.5',
      lg: 'h-10 rounded-md px-6 has-[>svg]:px-4',
      icon: 'size-9',
      'icon-xs': 'size-6 rounded-md [&_svg:not([class*="size-"])]:size-3',
      'icon-sm': 'size-8',
      'icon-lg': 'size-10',
    }
  },
  defaultVariants: { variant: 'default', size: 'default' }
})
export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof buttonVariants> & { asChild?: boolean; loading?: boolean; loadingLabel?: React.ReactNode }
export function Button({ className, variant = 'default', size = 'default', asChild, type = 'button', loading = false, loadingLabel, disabled, children, ...props }: ButtonProps) {
  const Comp = asChild ? Slot : 'button'
  return <Comp data-slot="button" data-variant={variant} data-size={size} type={type} className={cn(buttonVariants({ variant, size, className }))} {...props} disabled={disabled || loading} {...(loading ? { 'aria-busy': true, 'data-loading': true } : {})}>
    {loading && !asChild ? <><LoaderCircle className="button-loading-icon" data-slot="button-spinner" aria-hidden="true" /><span>{loadingLabel ?? children}</span></> : children}
  </Comp>
}
export { buttonVariants }
