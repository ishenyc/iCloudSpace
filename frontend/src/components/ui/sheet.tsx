import * as React from 'react'
import { Dialog as SheetPrimitive } from 'radix-ui'
import { AnimatePresence, m, useIsPresent, useReducedMotion } from 'motion/react'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { motionEase, motionTiming } from '@/lib/motion'

const SheetOpenContext = React.createContext(false)
export function Sheet({ open, defaultOpen = false, onOpenChange, ...props }: React.ComponentProps<typeof SheetPrimitive.Root>) {
  const [internalOpen, setInternalOpen] = React.useState(defaultOpen)
  const active = open ?? internalOpen
  return <SheetOpenContext.Provider value={active}><SheetPrimitive.Root data-slot="sheet" open={active} onOpenChange={next => { setInternalOpen(next); onOpenChange?.(next) }} {...props} /></SheetOpenContext.Provider>
}
export function SheetTrigger(props: React.ComponentProps<typeof SheetPrimitive.Trigger>) { return <SheetPrimitive.Trigger data-slot="sheet-trigger" {...props} /> }
export function SheetClose(props: React.ComponentProps<typeof SheetPrimitive.Close>) { return <SheetPrimitive.Close data-slot="sheet-close" {...props} /> }
type SheetContentProps = React.ComponentProps<typeof SheetPrimitive.Content> & { side?: 'top' | 'right' | 'bottom' | 'left'; showCloseButton?: boolean }
function SheetSurface({ className, children, side = 'right', showCloseButton = true, ...props }: SheetContentProps) {
  const present = useIsPresent()
  const reduced = useReducedMotion()
  const surface = React.useRef<HTMLDivElement>(null)
  const wasExiting = React.useRef(false)
  React.useEffect(() => {
    if (present && wasExiting.current && !surface.current?.contains(document.activeElement)) surface.current?.focus()
    wasExiting.current = !present
  }, [present])
  const offset = reduced ? { x: 0, y: 0 } : side === 'left' ? { x: -28, y: 0 } : side === 'right' ? { x: 28, y: 0 } : side === 'top' ? { x: 0, y: -24 } : { x: 0, y: 24 }
  return <>
    <SheetPrimitive.Overlay forceMount asChild data-slot="sheet-overlay"><m.div className="fixed inset-0 z-[100] bg-black/50" initial={{ opacity: reduced ? 1 : 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: reduced ? 0 : motionTiming.exit }} style={{ pointerEvents: present ? 'auto' : 'none' }} /></SheetPrimitive.Overlay>
    <SheetPrimitive.Content {...props} forceMount asChild data-slot="sheet-content">
      <m.div
        ref={surface}
        className={cn('fixed z-[101] flex flex-col gap-4 overflow-hidden bg-popover shadow-lg outline-none', side === 'right' && 'inset-y-3 right-3 h-[calc(100dvh-1.5rem)] w-[calc(100vw-1.5rem)] rounded-2xl border border-border sm:max-w-sm', side === 'left' && 'inset-y-0 left-0 h-full w-3/4 border-r border-border sm:max-w-sm', side === 'top' && 'inset-x-0 top-0 h-auto border-b border-border', side === 'bottom' && 'inset-x-0 bottom-0 h-auto border-t border-border', className)}
        inert={!present || undefined}
        aria-hidden={!present || undefined}
        initial={reduced ? false : { opacity: 0, ...offset }}
        animate={{ opacity: 1, x: 0, y: 0 }}
        exit={{ opacity: 0, ...offset, transition: { duration: reduced ? 0 : motionTiming.exit, ease: motionEase } }}
        transition={{ duration: reduced ? 0 : motionTiming.panel, ease: motionEase }}
        style={{ pointerEvents: present ? 'auto' : 'none' }}
      >{children}{showCloseButton && <SheetPrimitive.Close className="absolute top-4 right-4 rounded-xs opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus-visible:ring-2 focus-visible:ring-ring/25 focus-visible:outline-none disabled:pointer-events-none data-[state=open]:bg-secondary"><X className="size-4" /><span className="sr-only">关闭</span></SheetPrimitive.Close>}</m.div>
    </SheetPrimitive.Content>
  </>
}
export function SheetContent(props: SheetContentProps) {
  const open = React.useContext(SheetOpenContext)
  return <SheetPrimitive.Portal forceMount><AnimatePresence propagate>{open && <SheetSurface key="sheet-surface" {...props} />}</AnimatePresence></SheetPrimitive.Portal>
}
export function SheetHeader({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="sheet-header" className={cn('flex flex-col gap-1.5 p-4', className)} {...props} /> }
export function SheetFooter({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="sheet-footer" className={cn('mt-auto flex flex-col gap-2 p-4', className)} {...props} /> }
export function SheetTitle({ className, ...props }: React.ComponentProps<typeof SheetPrimitive.Title>) { return <SheetPrimitive.Title data-slot="sheet-title" className={cn('font-semibold text-foreground', className)} {...props} /> }
export function SheetDescription({ className, ...props }: React.ComponentProps<typeof SheetPrimitive.Description>) { return <SheetPrimitive.Description data-slot="sheet-description" className={cn('text-xs leading-relaxed text-muted-foreground', className)} {...props} /> }
