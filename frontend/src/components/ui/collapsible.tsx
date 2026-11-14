import * as React from 'react'
import { Collapsible as CollapsiblePrimitive } from 'radix-ui'
import { AnimatePresence, AnimatedSection } from '../../lib/motion'

const OpenContext = React.createContext(false)

export function Collapsible({ open, defaultOpen, onOpenChange, ...props }: React.ComponentProps<typeof CollapsiblePrimitive.Root>) {
  const [internal, setInternal] = React.useState(defaultOpen ?? false)
  const expanded = open ?? internal
  return <OpenContext.Provider value={expanded}><CollapsiblePrimitive.Root data-slot="collapsible" open={expanded} onOpenChange={value => { setInternal(value); onOpenChange?.(value) }} {...props} /></OpenContext.Provider>
}
export function CollapsibleTrigger(props: React.ComponentProps<typeof CollapsiblePrimitive.Trigger>) { return <CollapsiblePrimitive.Trigger data-slot="collapsible-trigger" {...props} /> }
export function CollapsibleContent({ children, forceMount, ...props }: React.ComponentProps<typeof CollapsiblePrimitive.Content>) {
  const open = React.useContext(OpenContext)
  return <AnimatePresence initial={false}>{(open || forceMount) && <CollapsiblePrimitive.Content data-slot="collapsible-content" forceMount asChild {...props}><AnimatedSection key="collapsible-content">{children}</AnimatedSection></CollapsiblePrimitive.Content>}</AnimatePresence>
}
