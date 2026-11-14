import * as React from 'react'
import { Progress as ProgressPrimitive } from 'radix-ui'
import { cn } from '@/lib/utils'

export function Progress({ className, value, max = 100, ...props }: React.ComponentProps<typeof ProgressPrimitive.Root>) {
  const limit = max > 0 ? max : 100
  const measured = typeof value === 'number' && Number.isFinite(value) ? Math.min(limit, Math.max(0, value)) : null
  return <ProgressPrimitive.Root data-slot="progress" value={measured} max={limit} className={cn('relative h-2 w-full overflow-hidden rounded-full bg-primary/20', className)} {...props}>
    <ProgressPrimitive.Indicator data-slot="progress-indicator" className={cn('h-full w-full flex-1 rounded-full bg-primary transition-transform duration-300', measured === null && 'w-1/3 animate-pulse motion-reduce:animate-none')} style={measured === null ? undefined : { transform: `translateX(-${100 - measured / limit * 100}%)` }} />
  </ProgressPrimitive.Root>
}
