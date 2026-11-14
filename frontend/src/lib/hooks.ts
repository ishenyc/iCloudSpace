import { useCallback, useEffect, useRef, useState } from 'react'

export function useResource<T = any>(loader: (signal: AbortSignal) => Promise<T>, deps: any[] = [], options: { poll?: boolean; keepPreviousData?: boolean; initialLoadingFeedback?: boolean } = {}) {
  const [result, setResult] = useState<{ data: T; key: string } | null>(null)
  const [failure, setFailure] = useState<{ error: any; key: string } | null>(null)
  const [settledKey, setSettledKey] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [manualKey, setManualKey] = useState<string | null>(null)
  const [initialFeedbackKey, setInitialFeedbackKey] = useState<string | null>(null)
  const loaderRef = useRef(loader); loaderRef.current = loader
  const refreshRef = useRef<() => Promise<void>>(async () => {})
  const depsKey = JSON.stringify(deps)
  useEffect(() => {
    let alive = true; let controller: AbortController | null = null; let timer: ReturnType<typeof setTimeout> | undefined; let generation = 0
    let manualOwner = 0
    let hasResult = Boolean(options.keepPreviousData && result)
    let initialTimer: ReturnType<typeof setTimeout> | undefined
    let initialVisibleAt = 0
    let feedbackTimer: ReturnType<typeof setTimeout> | undefined
    let finishFeedback: (() => void) | undefined
    const cancelFeedback = () => { clearTimeout(initialTimer); clearTimeout(feedbackTimer); const finish = finishFeedback; finishFeedback = undefined; finish?.() }
    const waitForFeedback = (duration: number) => duration > 0 ? new Promise<void>(resolve => { finishFeedback = resolve; feedbackTimer = setTimeout(() => { finishFeedback = undefined; resolve() }, duration) }) : Promise.resolve()
    if (!options.keepPreviousData) setResult(null)
    setFailure(null); setLoading(true); setManualKey(null); setInitialFeedbackKey(null)
    // Bind the loader to this effect's request identity, including imperative refreshes.
    const load = loaderRef.current
    const run = async (manual = false) => {
      // A focus/visibility event must not replace an in-flight manual refresh.
      if (!alive || (!manual && manualOwner)) return
      cancelFeedback()
      clearTimeout(timer); controller?.abort(); controller = new AbortController(); const signal = controller.signal; const id = ++generation
      const started = performance.now()
      const initialFeedback = options.initialLoadingFeedback && !hasResult
      // A focus-triggered replacement of this same first query must not hide
      // a loading frame that has already become visible.
      if (!initialFeedback) { initialVisibleAt = 0; setInitialFeedbackKey(null) }
      // Fast first reads render directly inside the route entrance. A loading
      // frame that is actually shown gets a short dwell, never a one-frame flash.
      if (initialFeedback && !initialVisibleAt) initialTimer = setTimeout(() => {
        if (alive && id === generation) { initialVisibleAt = performance.now(); setInitialFeedbackKey(depsKey) }
      }, 180)
      const settleInitialFeedback = async () => {
        if (!alive || id !== generation) return
        clearTimeout(initialTimer)
        if (initialVisibleAt) await waitForFeedback(240 - (performance.now() - initialVisibleAt))
      }
      if (manual) { manualOwner = id; setManualKey(depsKey) }
      setRefreshing(true); setFailure(null)
      try { const next = await load(signal); await settleInitialFeedback(); if (alive && id === generation) { hasResult = true; setResult({ data: next, key: depsKey }); setFailure(null) } }
      catch (e: any) { await settleInitialFeedback(); if (alive && id === generation && e?.name !== 'AbortError') setFailure({ error: e, key: depsKey }) }
      finally {
        if (alive && id === generation) {
          setSettledKey(depsKey); setLoading(false); setRefreshing(false); setInitialFeedbackKey(null); initialVisibleAt = 0
          if (manual) {
            const remaining = 300 - (performance.now() - started)
            await waitForFeedback(remaining)
            if (alive && id === generation) { manualOwner = 0; setManualKey(null) }
          }
          if (alive && id === generation && options.poll && !document.hidden) timer = setTimeout(() => void run(), 5000)
        }
      }
    }
    refreshRef.current = () => run(true)
    const visibility = () => { clearTimeout(timer); if (!document.hidden) void run() }
    const focus = () => { if (!document.hidden) void run() }
    void run()
    if (options.poll) { document.addEventListener('visibilitychange', visibility); window.addEventListener('focus', focus) }
    return () => { alive = false; generation++; controller?.abort(); clearTimeout(timer); cancelFeedback(); document.removeEventListener('visibilitychange', visibility); window.removeEventListener('focus', focus) }
  }, [depsKey, options.poll, options.keepPreviousData, options.initialLoadingFeedback])
  const refresh = useCallback(() => refreshRef.current(), [])
  const data = result && (options.keepPreviousData || result.key === depsKey) ? result.data : null
  const stale = data !== null && result?.key !== depsKey
  return { data, dataKey: data !== null ? result!.key : null, requestKey: depsKey, stale, error: failure?.key === depsKey ? failure.error : null, loading: loading || settledKey !== depsKey || (refreshing && result?.key !== depsKey), refreshing, manualRefreshing: manualKey === depsKey, initialLoadingVisible: !options.initialLoadingFeedback || initialFeedbackKey === depsKey, refresh }
}
export function useDebounced<T>(value: T, delay = 250) {
  const [next, setNext] = useState(value)
  useEffect(() => { const timer = setTimeout(() => setNext(value), delay); return () => clearTimeout(timer) }, [value, delay])
  return next
}
