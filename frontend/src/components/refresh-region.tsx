import type { ReactNode } from 'react'
import { LoaderCircle } from 'lucide-react'
import { AnimatePresence, m, useReducedMotion } from '../lib/motion'

export function ContentLoadingOverlay({ label = '正在刷新内容…' }: { label?: string }) {
  const reduced = useReducedMotion()
  return <m.div data-slot="content-refresh-loading" role="status" className="pointer-events-none absolute inset-0 z-10 rounded-[inherit] bg-background/70" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: reduced ? 0 : 0.12 }}>
    <div className="absolute inset-x-0 flex justify-center px-4" style={{ top: 'min(40%, 160px)' }}><span className="inline-flex items-center gap-2 rounded-full border border-border bg-popover px-3 py-2 text-xs text-foreground shadow-sm"><LoaderCircle aria-hidden="true" className="size-3.5 motion-safe:animate-spin" />{label}</span></div>
  </m.div>
}

/** A local read-result state; controls belong outside the inert result content. */
export function RefreshRegion({ loading, label, children }: { loading: boolean; label?: string; children: ReactNode }) {
  return <div data-slot="refresh-region" aria-busy={loading} style={{ position: 'relative', minWidth: 0, minHeight: loading ? 96 : undefined }}><div inert={loading || undefined} aria-hidden={loading || undefined}>{children}</div><AnimatePresence initial={false}>{loading && <ContentLoadingOverlay key="content-loading" label={label} />}</AnimatePresence></div>
}
