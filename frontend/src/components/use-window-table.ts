import { useCallback, useLayoutEffect, useRef, useState } from 'react'
import { useWindowVirtualizer } from '@tanstack/react-virtual'

// Sum layout offsets rather than transformed client rects: route/table entrance
// motion must not become a permanent offset in the window's virtual range.
function documentLayoutTop(element: HTMLElement) {
  let top = 0
  let node: HTMLElement | null = element
  while (node) {
    top += node.offsetTop
    node = node.offsetParent as HTMLElement | null
  }
  return top
}

/** Page scrolling owns the vertical axis; only large pages virtualize rows. */
export function useWindowTable<T>({ rows, rowKey, rowHeight, overscan = 8 }: {
  rows: T[]; rowKey: (row: T) => string | number; rowHeight: number; overscan?: number
}) {
  const body = useRef<HTMLTableSectionElement>(null)
  const [scrollMargin, setScrollMargin] = useState(0)
  const virtualized = rows.length > 100
  const updateMargin = useCallback(() => {
    if (body.current) {
      const next = documentLayoutTop(body.current)
      setScrollMargin(current => current === next ? current : next)
    }
  }, [])

  // React changes (filters, selection controls, columns) can move the table even
  // without resizing the viewport. Ancestor resize observation also covers CSS
  // sidebar transitions and asynchronously settling fonts/content.
  useLayoutEffect(() => { if (virtualized) updateMargin() })
  useLayoutEffect(() => {
    if (!virtualized || !body.current) return
    const observer = new ResizeObserver(updateMargin)
    let node: HTMLElement | null = body.current
    while (node) {
      observer.observe(node)
      node = node.parentElement
    }
    window.addEventListener('resize', updateMargin)
    return () => { observer.disconnect(); window.removeEventListener('resize', updateMargin) }
  }, [virtualized, updateMargin])

  const getItemKey = useCallback((index: number) => rows[index] ? rowKey(rows[index]) ?? index : index, [rows, rowKey])
  const estimateSize = useCallback(() => rowHeight, [rowHeight])
  const virtualizer = useWindowVirtualizer<HTMLTableRowElement>({
    count: rows.length, enabled: virtualized, estimateSize,
    getItemKey, overscan, scrollMargin,
  })
  // The document is not an internal list viewport. Measuring a row or receiving
  // a poll response must not issue an automatic window scroll correction.
  virtualizer.shouldAdjustScrollPositionOnItemSizeChange = () => false

  const measured = virtualizer.getVirtualItems().filter(item => item.index < rows.length)
  // Bootstrap useful content before the first window measurement, with a full
  // spacer so later rows remain reachable from the document scrollbar.
  const items = virtualized && measured.length ? measured : rows.slice(0, virtualized ? 20 : rows.length).map((row, index) => ({
    index, key: getItemKey(index), start: scrollMargin + index * rowHeight, end: scrollMargin + (index + 1) * rowHeight,
  }))
  const paddingTop = virtualized ? Math.max(0, (items[0]?.start ?? scrollMargin) - scrollMargin) : 0
  const paddingBottom = virtualized ? Math.max(0, virtualizer.getTotalSize() - ((items.at(-1)?.end ?? scrollMargin) - scrollMargin)) : 0
  return { body, virtualized, virtualizer, items, paddingTop, paddingBottom }
}
