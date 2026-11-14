import * as React from 'react'
import { Tabs as TabsPrimitive } from 'radix-ui'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'
import { m, motionEase, useReducedMotion } from '@/lib/motion'

const ValueContext = React.createContext({ value: '', id: '' })
const VariantContext = React.createContext<'default' | 'line'>('default')
export function Tabs({ className, orientation = 'horizontal', value, defaultValue, onValueChange, ...props }: React.ComponentProps<typeof TabsPrimitive.Root>) {
  const [internal, setInternal] = React.useState(defaultValue || '')
  const id = React.useId()
  const active = value ?? internal
  return <ValueContext.Provider value={{ value: active, id }}><TabsPrimitive.Root data-slot="tabs" data-orientation={orientation} orientation={orientation} value={active} onValueChange={next => { setInternal(next); onValueChange?.(next) }} className={cn('group/tabs flex gap-2 data-[orientation=horizontal]:flex-col', className)} {...props} /></ValueContext.Provider>
}
const tabsListVariants = cva('group/tabs-list inline-flex w-fit items-center justify-center rounded-lg p-[3px] text-muted-foreground group-data-[orientation=horizontal]/tabs:h-9 group-data-[orientation=vertical]/tabs:h-fit group-data-[orientation=vertical]/tabs:flex-col data-[variant=line]:rounded-none', { variants: { variant: { default: 'bg-muted', line: 'gap-1 bg-transparent' } }, defaultVariants: { variant: 'default' } })
export function TabsList({ className, variant = 'default', ...props }: React.ComponentProps<typeof TabsPrimitive.List> & VariantProps<typeof tabsListVariants>) {
  return <VariantContext.Provider value={variant || 'default'}><TabsPrimitive.List data-slot="tabs-list" data-variant={variant} className={cn(tabsListVariants({ variant }), className)} {...props} /></VariantContext.Provider>
}
export function TabsTrigger({ className, children, value, ...props }: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
  const active = React.useContext(ValueContext)
  const variant = React.useContext(VariantContext)
  const reduced = useReducedMotion()
  return <TabsPrimitive.Trigger data-slot="tabs-trigger" value={value} className={cn('relative isolate inline-flex h-[calc(100%-1px)] flex-1 items-center justify-center gap-1.5 rounded-md border border-transparent px-3 py-1 text-sm font-medium whitespace-nowrap text-muted-foreground transition-colors hover:text-foreground focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/25 focus-visible:outline-none disabled:pointer-events-none disabled:opacity-50 data-[state=active]:text-foreground group-data-[orientation=vertical]/tabs:w-full group-data-[orientation=vertical]/tabs:justify-start [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*="size-"])]:size-4', className)} {...props}>
    {active.value === value && <m.span data-slot="tabs-indicator" data-variant={variant} layoutId={`tabs-${active.id}`} className="tabs-indicator" transition={{ duration: reduced ? 0 : .18, ease: motionEase }} />}
    {children}
  </TabsPrimitive.Trigger>
}
export function TabsContent({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Content>) { return <TabsPrimitive.Content data-slot="tabs-content" className={cn('flex-1 outline-none', className)} {...props} /> }
export { tabsListVariants }
