import { useEffect, useRef, useState } from 'react'
import { LoaderCircle, RefreshCw } from 'lucide-react'
import { Button, type ButtonProps } from './ui/button'
import { useToast } from './ui'
import { cn } from '../lib/utils'

type RefreshButtonProps = Omit<ButtonProps, 'onClick' | 'asChild'> & {
  onRefresh: () => void | Promise<unknown>
  pending?: boolean
  loadingLabel?: string
  onBusyChange?: (busy: boolean) => void
}

/** Manual feedback is independent of polling, and lasts through the real request. */
export function RefreshButton({ onRefresh, pending = false, loadingLabel = '刷新中…', children = '刷新', disabled, className, onBusyChange, 'aria-label': label, ...props }: RefreshButtonProps) {
  const [working, setWorking] = useState(false)
  const lock = useRef(false)
  const mounted = useRef(true)
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const toast = useToast()
  const busy = pending || working
  const busyListener = useRef(onBusyChange); busyListener.current = onBusyChange
  useEffect(() => { busyListener.current?.(busy) }, [busy])
  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false; clearTimeout(timer.current); busyListener.current?.(false) }
  }, [])
  async function refresh() {
    if (lock.current || pending || disabled) return
    lock.current = true; setWorking(true)
    const started = performance.now()
    try { await onRefresh() }
    catch (error: any) { if (mounted.current) toast(error?.message || '刷新失败，请重试。', 'error') }
    finally {
      if (mounted.current) timer.current = setTimeout(() => { lock.current = false; setWorking(false) }, Math.max(0, 300 - (performance.now() - started)))
      else lock.current = false
    }
  }
  return <Button {...props} className={cn(className, busy && 'disabled:opacity-80')} data-refresh-button="" data-loading={busy || undefined} aria-label={label || (typeof children === 'string' ? children : undefined)} aria-busy={busy} disabled={disabled || busy} onClick={() => void refresh()}>
    {busy ? <LoaderCircle data-slot="refresh-spinner" aria-hidden="true" className="size-4 motion-safe:animate-spin" /> : <RefreshCw aria-hidden="true" className="size-4" />}
    <span>{children}</span><span className="sr-only" role="status">{busy ? loadingLabel : ''}</span>
  </Button>
}
