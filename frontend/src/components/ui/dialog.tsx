import * as React from 'react'
import { Dialog as DialogPrimitive } from 'radix-ui'
import { AnimatePresence, m, useIsPresent, useReducedMotion } from 'motion/react'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { motionEase, motionTiming } from '@/lib/motion'

const DialogOpenContext = React.createContext(false)
export function Dialog({ open, defaultOpen = false, onOpenChange, ...props }: React.ComponentProps<typeof DialogPrimitive.Root>) {
  const [internalOpen, setInternalOpen] = React.useState(defaultOpen)
  const active = open ?? internalOpen
  return <DialogOpenContext.Provider value={active}><DialogPrimitive.Root data-slot="dialog" open={active} onOpenChange={next => { setInternalOpen(next); onOpenChange?.(next) }} {...props} /></DialogOpenContext.Provider>
}
export function DialogTrigger(props: React.ComponentProps<typeof DialogPrimitive.Trigger>) { return <DialogPrimitive.Trigger data-slot="dialog-trigger" {...props} /> }
export function DialogClose(props: React.ComponentProps<typeof DialogPrimitive.Close>) { return <DialogPrimitive.Close data-slot="dialog-close" {...props} /> }
export function DialogPortal(props: React.ComponentProps<typeof DialogPrimitive.Portal>) { return <DialogPrimitive.Portal data-slot="dialog-portal" {...props} /> }
export function DialogOverlay({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Overlay>) { return <DialogPrimitive.Overlay data-slot="dialog-overlay" className={cn('fixed inset-0 z-[100] bg-black/50', className)} {...props} /> }

type DialogContentProps = React.ComponentProps<typeof DialogPrimitive.Content> & { showCloseButton?: boolean }
function DialogSurface({ className, children, showCloseButton = true, ...props }: DialogContentProps) {
  const present = useIsPresent()
  const reduced = useReducedMotion()
  const surface = React.useRef<HTMLDivElement>(null)
  const wasExiting = React.useRef(false)
  React.useEffect(() => {
    // A quick reopen reuses the exiting node, so Radix's mount autofocus does
    // not fire again. Restore a safe focus target when the node becomes live.
    if (present && wasExiting.current && !surface.current?.contains(document.activeElement)) surface.current?.focus()
    wasExiting.current = !present
  }, [present])
  const transition = { duration: reduced ? 0 : motionTiming.panel, ease: motionEase }
  // Fixed dialogs enter/exit explicitly. Layout projection would measure and
  // reset their transform again on unrelated background list polls.
  return <>
    <DialogOverlay forceMount asChild><m.div initial={{ opacity: reduced ? 1 : 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: reduced ? 0 : motionTiming.exit }} style={{ pointerEvents: present ? 'auto' : 'none' }} /></DialogOverlay>
    <DialogPrimitive.Content {...props} forceMount asChild data-slot="dialog-content">
      <m.div
        ref={surface}
        className={cn('fixed top-[50%] left-[50%] z-[101] grid w-full max-w-[calc(100%-2rem)] translate-x-[-50%] translate-y-[-50%] gap-4 rounded-lg border border-border bg-background p-6 shadow-lg outline-none sm:max-w-lg', className)}
        inert={!present || undefined}
        aria-hidden={!present || undefined}
        initial={reduced ? false : { opacity: 0, y: 10, scale: .985 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: reduced ? 0 : 6, scale: reduced ? 1 : .99, transition: { duration: reduced ? 0 : motionTiming.exit, ease: motionEase } }}
        transition={transition}
        style={{ pointerEvents: present ? 'auto' : 'none' }}
      >{children}{showCloseButton && <DialogPrimitive.Close data-slot="dialog-close" className="absolute top-4 right-4 rounded-xs opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus-visible:ring-2 focus-visible:ring-ring/25 focus-visible:outline-none disabled:pointer-events-none data-[state=open]:bg-accent data-[state=open]:text-muted-foreground"><X className="size-4" /><span className="sr-only">关闭</span></DialogPrimitive.Close>}</m.div>
    </DialogPrimitive.Content>
  </>
}
export function DialogContent(props: DialogContentProps) {
  const open = React.useContext(DialogOpenContext)
  return <DialogPortal forceMount><AnimatePresence propagate>{open && <DialogSurface key="dialog-surface" {...props} />}</AnimatePresence></DialogPortal>
}
export function DialogHeader({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="dialog-header" className={cn('flex flex-col gap-2 text-center sm:text-left', className)} {...props} /> }
export function DialogFooter({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="dialog-footer" className={cn('flex flex-col-reverse gap-2 sm:flex-row sm:justify-end', className)} {...props} /> }
export function DialogTitle({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Title>) { return <DialogPrimitive.Title data-slot="dialog-title" className={cn('text-base leading-snug font-semibold', className)} {...props} /> }
export function DialogDescription({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Description>) { return <DialogPrimitive.Description data-slot="dialog-description" className={cn('text-xs leading-relaxed text-muted-foreground', className)} {...props} /> }
