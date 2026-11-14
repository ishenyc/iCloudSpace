import { useCallback, useLayoutEffect, useRef, type ReactNode } from 'react'
import { useAnimationControls } from 'motion/react'
import { AnimatePresence, m, motionEase, useReducedMotion } from '../lib/motion'
import { ContentLoadingOverlay } from './refresh-region'

/** Preserve the scroll container and query-bound results; polling never replays entry. */
export function TableTransition({ dataKey, stale, pending, refreshing = false, manualRefreshing = false, initialLoadingVisible = true, label = '正在更新列表', children }: {
  dataKey: string | null; stale: boolean; pending: boolean; refreshing?: boolean; manualRefreshing?: boolean; initialLoadingVisible?: boolean; label?: string; children: ReactNode
}) {
  const contentLoading = dataKey !== null && (manualRefreshing || pending)
  const waitingForFeedback = dataKey === null && pending && !initialLoadingVisible
  const reduced = useReducedMotion()
  const region = useRef<HTMLDivElement>(null)
  const content = useRef<HTMLDivElement>(null)
  const appearance = useAnimationControls()
  const size = useAnimationControls()
  const previousKey = useRef(dataKey)
  const previousHeight = useRef(0)
  const resizing = useRef(false)
  const revision = useRef(0)
  const horizontal = useRef(0)
  const heightTarget = useRef(0)
  const releaseTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const releaseSize = useCallback(() => {
    revision.current++; clearTimeout(releaseTimer.current)
    resizing.current = false; size.stop(); size.set({ height: 'auto', overflow: 'visible' })
  }, [size])

  useLayoutEffect(() => {
    const node = content.current
    if (!node) return
    previousHeight.current = node.offsetHeight
    const observer = new ResizeObserver(() => {
      const height = node.offsetHeight
      previousHeight.current = height
      // Font/virtualizer measurements can settle after the query commit. Never
      // keep a stale numeric height that clips rows once their real height arrives.
      if (resizing.current && Math.abs(height - heightTarget.current) > 2) releaseSize()
    })
    observer.observe(node)
    return () => observer.disconnect()
  }, [releaseSize])

  useLayoutEffect(() => {
    const next = content.current
    if (!next) return
    const changed = previousKey.current !== dataKey
    const firstDataset = previousKey.current === null
    appearance.stop()
    if (reduced) releaseSize()
    if (waitingForFeedback) { appearance.set({ opacity: 0, y: 0 }); releaseSize(); return }
    if (stale || contentLoading) {
      // The loading veil owns attenuation; do not multiply it by a second fade.
      void appearance.start({ opacity: contentLoading ? 1 : 0.7, y: 0, transition: { duration: reduced ? 0 : 0.12, ease: motionEase } })
      return
    }
    previousKey.current = dataKey
    // First data is part of the page entrance, not another dataset transition.
    // Also avoid animating the placeholder's height into a full table.
    if (firstDataset || dataKey === null) {
      appearance.set({ opacity: 1, y: 0 }); releaseSize(); return
    }
    if (!changed) {
      void appearance.start({ opacity: 1, y: 0, transition: { duration: reduced ? 0 : 0.16, ease: motionEase } })
      return
    }

    // Page scrolling owns the vertical axis; retain horizontal table position.
    next.querySelectorAll<HTMLElement>('.table-wrap').forEach(node => { node.scrollLeft = horizontal.current })
    appearance.set({ opacity: reduced ? 1 : 0.6, y: reduced ? 0 : 4 })
    void appearance.start({ opacity: 1, y: 0, transition: { duration: reduced ? 0 : 0.2, ease: motionEase } })

    const from = resizing.current ? region.current?.getBoundingClientRect().height || previousHeight.current : previousHeight.current
    const to = next.offsetHeight
    previousHeight.current = to
    const id = ++revision.current
    size.stop(); clearTimeout(releaseTimer.current)
    if (reduced || Math.abs(from - to) < 2) {
      releaseSize()
      return
    }
    resizing.current = true
    heightTarget.current = to
    size.set({ height: from, overflow: 'clip' })
    // Feature loading/interruption cannot leave the result region height-locked.
    releaseTimer.current = setTimeout(() => { if (revision.current === id) releaseSize() }, 280)
    // Only this bounded result region animates height; text is never scaled.
    void size.start({ height: to, transition: { duration: 0.2, ease: motionEase } }).then(() => {
      if (revision.current !== id) return
      releaseSize()
    })
  }, [dataKey, stale, contentLoading, waitingForFeedback, reduced, appearance, size, releaseSize])

  useLayoutEffect(() => () => { revision.current++; clearTimeout(releaseTimer.current); appearance.stop(); size.stop() }, [appearance, size])

  return <m.div ref={region} className="table-transition" data-motion="table-results" data-state={waitingForFeedback ? 'waiting' : contentLoading || (pending && dataKey === null) ? 'pending' : stale ? 'stale' : 'ready'} data-refreshing={refreshing || undefined} data-manual-refreshing={manualRefreshing || undefined} aria-busy={pending || refreshing || manualRefreshing} initial={false} animate={size} onScrollCapture={event => { const node = event.target as HTMLElement; if (node.matches('.table-wrap')) horizontal.current = node.scrollLeft }} style={{ position: 'relative', minWidth: 0 }}>
    <m.div ref={content} initial={{ opacity: waitingForFeedback ? 0 : 1, y: 0 }} animate={appearance} inert={waitingForFeedback || stale || contentLoading || undefined} aria-hidden={waitingForFeedback || stale || contentLoading || undefined} style={{ display: 'flow-root', minWidth: 0, pointerEvents: waitingForFeedback || stale || contentLoading ? 'none' : undefined }}>{children}</m.div>
    <AnimatePresence initial={false}>{contentLoading && <ContentLoadingOverlay key="manual-content-loading" label={label} />}</AnimatePresence>
    <AnimatePresence initial={false}>{dataKey !== null && (pending || refreshing) && <m.div key="table-progress" role="progressbar" aria-label={label} initial={{ opacity: 0 }} animate={{ opacity: 1, transition: { delay: .18, duration: reduced ? 0 : .12 } }} exit={{ opacity: 0, transition: { duration: reduced ? 0 : .1 } }} style={{ position: 'absolute', top: 0, left: 10, right: 10, height: 2, overflow: 'hidden', borderRadius: 2, pointerEvents: 'none', zIndex: 3 }}><m.div initial={false} animate={reduced ? { x: 0 } : { x: ['-100%', '400%'] }} transition={reduced ? { duration: 0 } : { duration: 1.2, repeat: Infinity, ease: 'linear' }} style={{ height: '100%', width: reduced ? '100%' : '25%', background: 'var(--foreground)', opacity: .3 }} /></m.div>}</AnimatePresence>
    <span className="sr-only" role="status">{stale ? pending ? label : '列表更新失败，请重试。' : ''}</span>
  </m.div>
}
