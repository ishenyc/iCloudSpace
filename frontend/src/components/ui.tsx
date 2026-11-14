import { copyText } from '../lib/clipboard'
import { Children, Fragment, createContext, isValidElement, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode, type ComponentProps, type SelectHTMLAttributes } from 'react'
import { createPortal } from 'react-dom'
import { AnimatePresence, m, useIsPresent, useReducedMotion } from 'motion/react'
import { AlertCircle, ArrowLeft, ArrowRight, Check, CircleCheck, Copy, Inbox, Info, Loader2, TriangleAlert, X } from 'lucide-react'
import { cn } from '../lib/utils'
import { motionEase, motionTiming } from '../lib/motion'
import { CopyStatusIcon } from './animated-icon'
import { ControlError, controlErrorMessage } from '../transport/errors'
import { feedbackDetails, feedbackIsVisible, feedbackMessage, feedbackPresentation, feedbackSignature, type FeedbackContext } from '../lib/feedback'
export { Button } from './ui/button'
import { Button } from './ui/button'
import { Input as ShadcnInput } from './ui/input'
import { Textarea as ShadcnTextarea } from './ui/textarea'
import { Badge as ShadcnBadge } from './ui/badge'
import { Alert as ShadcnAlert, AlertDescription } from './ui/alert'
import { Select as SelectRoot, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from './ui/select'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { Sheet as SheetRoot, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from './ui/sheet'
import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider as ShadcnTooltipProvider } from './ui/tooltip'
export { Checkbox } from './ui/checkbox'
export { Switch } from './ui/switch'
export { Progress } from './ui/progress'
export { Tabs, TabsList, TabsTrigger, TabsContent } from './ui/tabs'
export * from './ui/dropdown-menu'
export * from './ui/collapsible'
export * from './ui/table'

const FieldContext = createContext<{ controlId: string; labelId: string; descriptionId?: string } | undefined>(undefined)
const ToastHostContext = createContext<(node: HTMLElement) => () => void>(() => () => {})
function useToastHost(surface: { current: HTMLDivElement | null }, active: boolean) {
  const register = useContext(ToastHostContext)
  useEffect(() => { if (active && surface.current) return register(surface.current) }, [active, register, surface])
}
export function Input({ className, id, 'aria-label': label, 'aria-labelledby': labelledBy, 'aria-describedby': describedBy, ...props }: ComponentProps<'input'>) {
  const field = useContext(FieldContext)
  return <ShadcnInput id={id || field?.controlId} aria-label={label} aria-labelledby={labelledBy || (!label ? field?.labelId : undefined)} aria-describedby={[describedBy, field?.descriptionId].filter(Boolean).join(' ') || undefined} className={cn('input', className)} {...props} />
}
export function Textarea({ className, id, 'aria-label': label, 'aria-labelledby': labelledBy, 'aria-describedby': describedBy, ...props }: ComponentProps<'textarea'>) {
  const field = useContext(FieldContext)
  return <ShadcnTextarea id={id || field?.controlId} aria-label={label} aria-labelledby={labelledBy || (!label ? field?.labelId : undefined)} aria-describedby={[describedBy, field?.descriptionId].filter(Boolean).join(' ') || undefined} className={cn('input min-h-28 resize-y leading-relaxed', className)} {...props} />
}
type SelectProps = Pick<SelectHTMLAttributes<HTMLSelectElement>, 'className' | 'children' | 'value' | 'defaultValue' | 'disabled' | 'required' | 'name' | 'id' | 'aria-label' | 'aria-labelledby' | 'aria-describedby' | 'aria-invalid' | 'style' | 'autoFocus' | 'title' | 'tabIndex'> & { onChange?: (event: { target: { value: string } }) => void }
// Existing API fields use <option> declarations. Adapt those declarations once,
// while the visible control, keyboard navigation and popover are shadcn/Radix.
// Prefix every wire value so an empty string remains a selectable real option.
const selectValue = (value: unknown) => `option:${String(value ?? '')}`
function selectOptions(children: ReactNode): ReactNode {
  return Children.map(children, child => {
    if (!isValidElement<{ children?: ReactNode; value?: string | number; label?: string; disabled?: boolean }>(child)) return null
    if (child.type === Fragment) return selectOptions(child.props.children)
    if (child.type === 'optgroup') return <SelectGroup><SelectLabel>{child.props.label}</SelectLabel>{selectOptions(child.props.children)}</SelectGroup>
    if (child.type !== 'option') return null
    return <SelectItem value={selectValue(child.props.value ?? child.props.children)} disabled={child.props.disabled}>{child.props.children}</SelectItem>
  })
}
export function Select({ className, children, value, defaultValue, disabled, required, name, onChange, id, 'aria-label': label, 'aria-labelledby': labelledBy, 'aria-describedby': describedBy, ...props }: SelectProps) {
  const field = useContext(FieldContext)
  return <SelectRoot value={value === undefined ? undefined : selectValue(value)} defaultValue={defaultValue === undefined ? undefined : selectValue(defaultValue)} disabled={disabled} required={required} name={name} onValueChange={next => onChange?.({ target: { value: next.slice('option:'.length) } })}>
    <SelectTrigger id={id || field?.controlId} aria-label={label} aria-labelledby={labelledBy || (!label ? field?.labelId : undefined)} aria-describedby={[describedBy, field?.descriptionId].filter(Boolean).join(' ') || undefined} className={cn('input w-full min-w-0', className)} {...props}><SelectValue /></SelectTrigger><SelectContent>{selectOptions(children)}</SelectContent>
  </SelectRoot>
}
export function Badge({ tone = 'neutral', children, className }: { tone?: 'neutral' | 'success' | 'warning' | 'danger'; children: ReactNode; className?: string }) {
  return <ShadcnBadge variant="outline" className={cn('gap-1.5', tone === 'neutral' && 'text-muted-foreground', tone === 'success' && 'border-emerald-500/20 bg-emerald-500/5 text-emerald-700 dark:text-emerald-400', tone === 'warning' && 'border-amber-500/20 bg-amber-500/5 text-amber-700 dark:text-amber-400', tone === 'danger' && 'border-destructive/20 bg-destructive/5 text-destructive', className)}><span aria-hidden="true" className="size-1 rounded-full bg-current opacity-75" />{children}</ShadcnBadge>
}
export function Field({ label, description, children }: { label: ReactNode; description?: ReactNode; children: ReactNode }) {
  const id = useId()
  const controlId = `${id}-control`, labelId = `${id}-label`, descriptionId = description ? `${id}-description` : undefined
  return <FieldContext.Provider value={{ controlId, labelId, descriptionId }}><label className="field" htmlFor={controlId}><span id={labelId} className="field-label">{label}</span>{children}{description && <span id={descriptionId} className="field-description">{description}</span>}</label></FieldContext.Provider>
}
type OverlayProps = { open: boolean; onOpenChange: (open: boolean) => void; title: string; description?: ReactNode; children: ReactNode; footer?: ReactNode; wide?: boolean; className?: string; bodyClassName?: string }
function useOverlayFocus() {
  const previous = useRef<HTMLElement | null>(null)
  return {
    remember: () => { previous.current = document.activeElement as HTMLElement | null },
    restore: (event: Event) => {
      event.preventDefault()
      requestAnimationFrame(() => {
        const target = previous.current
        if (target?.isConnected && !target.closest('[aria-hidden="true"]')) { target.focus(); return }
        const surfaces = document.querySelectorAll<HTMLElement>('[role="dialog"][data-state="open"]')
        const fallback = surfaces.item(surfaces.length - 1) || document.getElementById('main-content')
        fallback?.focus()
      })
    },
  }
}
export function Modal({ open, onOpenChange, title, description, children, footer, wide, className, bodyClassName }: OverlayProps) {
  const surfaceRef = useRef<HTMLDivElement>(null)
  const focus = useOverlayFocus()
  const present = useIsPresent()
  useToastHost(surfaceRef, open && present)
  return <Dialog open={open && present} onOpenChange={onOpenChange}><DialogContent ref={surfaceRef} onOpenAutoFocus={focus.remember} onCloseAutoFocus={focus.restore} className={cn('flex max-h-[calc(100dvh-2rem)] flex-col gap-0 overflow-hidden p-0', wide && 'sm:max-w-3xl', className)}>
    <DialogHeader className="dialog-header shrink-0 border-b border-border p-6 pr-12 text-left"><DialogTitle>{title}</DialogTitle><DialogDescription className={description ? undefined : 'sr-only'}>{description || title}</DialogDescription></DialogHeader>
    <div className={cn('dialog-body min-h-0 overflow-y-auto p-6', bodyClassName)}>{children}</div>{footer && <DialogFooter className="dialog-footer shrink-0 border-t border-border p-4 sm:px-6">{footer}</DialogFooter>}
  </DialogContent></Dialog>
}
export function Sheet({ open, onOpenChange, title, description, children, footer, wide, className, bodyClassName }: OverlayProps) {
  const surfaceRef = useRef<HTMLDivElement>(null)
  const focus = useOverlayFocus()
  const present = useIsPresent()
  useToastHost(surfaceRef, open && present)
  return <SheetRoot open={open && present} onOpenChange={onOpenChange}><SheetContent ref={surfaceRef} data-wide={wide || undefined} onOpenAutoFocus={event => { focus.remember(); event.preventDefault(); surfaceRef.current?.focus() }} onCloseAutoFocus={focus.restore} className={cn('w-full gap-0 sm:max-w-xl', wide && 'sm:max-w-3xl', className)}>
    <SheetHeader className="dialog-header shrink-0 border-b border-border p-6 pr-12"><SheetTitle>{title}</SheetTitle><SheetDescription className={description ? undefined : 'sr-only'}>{description || title}</SheetDescription></SheetHeader>
    <div className={cn('dialog-body min-h-0 flex-1 overflow-y-auto p-6', bodyClassName)}>{children}</div>{footer && <SheetFooter className="dialog-footer shrink-0 flex-row flex-wrap justify-end border-t border-border p-4 sm:px-6">{footer}</SheetFooter>}
  </SheetContent></SheetRoot>
}
export function Tip({ label, children, enabled = true }: { label: string; children: ReactNode; enabled?: boolean }) {
  const [open, setOpen] = useState(false)
  useEffect(() => { if (!enabled) setOpen(false) }, [enabled])
  return <Tooltip open={enabled && open} onOpenChange={next => setOpen(enabled && next)}><TooltipTrigger asChild>{children}</TooltipTrigger>{enabled && <TooltipContent side="right" sideOffset={10}>{label}</TooltipContent>}</Tooltip>
}
export function TooltipProvider({ children }: { children: ReactNode }) { return <ShadcnTooltipProvider delayDuration={320} skipDelayDuration={100}>{children}</ShadcnTooltipProvider> }
export function Alert({ error, children, tone = 'danger', attention = error ? 'notify' : 'none', title, actions }: { error?: any; children?: ReactNode; tone?: string; attention?: 'focus' | 'notify' | 'none'; title?: string; actions?: ReactNode }) {
  const surface = useRef<HTMLDivElement>(null), noticed = useRef(''), id = useId(), toast = useToast(), reduced = useReducedMotion()
  const controlled = error instanceof ControlError
  const message = controlled ? controlErrorMessage(error) : error?.message || (typeof error === 'string' ? error : null)
  useEffect(() => {
    const node = surface.current
    if (!node || attention === 'none') return
    const signature = feedbackSignature(error, message || node.textContent || '')
    if (noticed.current === signature) return
    const frame = requestAnimationFrame(() => {
      if (!node.isConnected || !node.getClientRects().length) return
      const dialogs = document.querySelectorAll<HTMLElement>('[role="dialog"][data-state="open"]')
      const dialog = dialogs[dialogs.length - 1]
      if (dialog && !dialog.contains(node)) return
      noticed.current = signature
      const reveal = () => { if (node.isConnected) { node.scrollIntoView({ block: 'nearest', behavior: reduced ? 'auto' : 'smooth' }); node.focus({ preventScroll: true }) } }
      if (attention === 'focus') { reveal(); return }
      const clips = [{ top: 76, left: 0, right: innerWidth, bottom: innerHeight }]
      for (let parent = node.parentElement; parent; parent = parent.parentElement) {
        const style = getComputedStyle(parent)
        if (/(auto|scroll|hidden|clip)/.test(style.overflow + style.overflowY)) clips.push(parent.getBoundingClientRect())
      }
      if (!feedbackIsVisible(node.getBoundingClientRect(), clips)) toast('当前区域有一项需要处理的提示。', 'error', { key: 'alert-' + id + signature, action: { label: '查看提示', run: reveal } })
    })
    return () => cancelAnimationFrame(frame)
  }, [error, message, children, attention, id, toast, reduced])
  if (!error && !children) return null
  const heading = title || (error ? controlled && (error.outcome === 'unknown' || /UNKNOWN|UNSETTLED|UNCONFIRMED/.test(error.code)) ? '结果待确认' : '操作未完成' : null)
  const Icon = tone === 'danger' ? AlertCircle : tone === 'warning' ? TriangleAlert : tone === 'success' ? CircleCheck : Info
  return <ShadcnAlert ref={surface} tabIndex={-1} aria-labelledby={heading ? id : undefined} role={tone === 'danger' ? 'alert' : 'status'} className="system-alert" data-tone={tone} data-has-actions={Boolean(actions) || undefined}>
    <span className="system-alert-icon" aria-hidden="true"><Icon /></span>
    <AlertDescription>{heading && <div id={id} className="system-alert-title">{heading}</div>}<div className="system-alert-message">{message || children}</div>{message && children && <div className="system-alert-context">{children}</div>}{(controlled || error?.requestId) && <details className="operation-details"><summary>查看错误详情</summary><div className="system-alert-request">{controlled && <><span>错误代码</span><code>{error.code}</code></>}{error?.requestId && <><span>请求编号</span><code>{error.requestId}</code></>}</div></details>}</AlertDescription>
    {actions && <div className="system-alert-actions">{actions}</div>}
  </ShadcnAlert>
}
export function Empty({ title, description, action, compact = false }: { title: string; description?: ReactNode; action?: ReactNode; compact?: boolean }) { return <div className={cn('empty', compact && 'empty-compact')}><div className="empty-icon"><Inbox size={compact ? 19 : 25} strokeWidth={1.3} /></div><h3>{title}</h3>{description && <p>{description}</p>}{action}</div> }
export function Loading({ label = '正在加载' }: { label?: string }) { return <div className="loading" role="status"><Loader2 className="spin" size={18} />{label}</div> }
export function PageHeader({ title, description, actions, eyebrow }: { title: string; description?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) { return <div className="page-heading"><div>{eyebrow && <div className="eyebrow">{eyebrow}</div>}<h1>{title}</h1>{description && <p>{description}</p>}</div>{actions && <div className="page-actions">{actions}</div>}</div> }
export function Panel({ title, description, actions, children }: { title?: ReactNode; description?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  const hasBody = Children.toArray(children).length > 0
  return <section className="panel" data-has-body={hasBody}>{(title || actions) && <header className="panel-header"><div>{title && <h2>{title}</h2>}{description && <p>{description}</p>}</div>{actions && <div className="row-actions">{actions}</div>}</header>}{hasBody && <div className="panel-body">{children}</div>}</section>
}
export function Pagination({ page, size, total, onPage, onSize, disabled = false }: { page: number; size: number; total: number; onPage: (page: number) => void; onSize: (size: number) => void; disabled?: boolean }) {
  const pages = size ? Math.max(1, Math.ceil(total / size)) : 1
  return <div className="pagination" aria-busy={disabled}><span>共 <strong>{total}</strong> 条</span><div className="pagination-controls"><label className="pagination-size">每页<Select aria-label="每页条数" value={size} onChange={e => onSize(Number(e.target.value))}>{[20, 50, 100, 500, 1000, 0].map(n => <option key={n} value={n}>{n || '全部'}</option>)}</Select></label><span className="mono">{Math.min(page, pages)} / {pages}</span><Button variant="ghost" size="icon" disabled={disabled || page <= 1} onClick={() => onPage(page - 1)} aria-label="上一页"><ArrowLeft size={15} /></Button><Button variant="ghost" size="icon" disabled={disabled || page >= pages} onClick={() => onPage(page + 1)} aria-label="下一页"><ArrowRight size={15} /></Button></div></div>
}
export { copyText } from '../lib/clipboard'
export function CopyButton({ value, label = '复制' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false); const toast = useToast()
  return <Button variant="secondary" size="sm" className="copy-button" onClick={async () => { try { await copyText(value); setCopied(true); setTimeout(() => setCopied(false), 1800) } catch (e: any) { toast(e.message, 'error') } }}><CopyStatusIcon copied={copied} size={14} />{copied ? '已复制' : label}</Button>
}
type ToastOptions = { key?: string; action?: { label: string; run: () => void }; details?: { code: string; requestId?: string } }
type ToastFn = (message: string, tone?: 'success' | 'error' | 'info', options?: ToastOptions) => void
const ToastContext = createContext<ToastFn>(() => {})
type ToastItem = ToastOptions & { id: number; message: string; tone: string }
function ToastMessage({ item, dismiss }: { item: ToastItem; dismiss: () => void }) {
  const reduced = useReducedMotion()
  const present = useIsPresent()
  const [hovered, setHovered] = useState(false), [focused, setFocused] = useState(false), [expanded, setExpanded] = useState(false)
  const close = useRef(dismiss); close.current = dismiss
  useEffect(() => { if (hovered || focused || expanded) return; const timer = setTimeout(() => close.current(), item.tone === 'error' || item.action ? 8000 : 3500); return () => clearTimeout(timer) }, [item.id, item.tone, item.action, hovered, focused, expanded])
  return <m.div layout={reduced ? false : 'position'} className={cn('toast', `toast-${item.tone}`)} role={item.tone === 'error' ? 'alert' : 'status'} onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)} onFocusCapture={() => setFocused(true)} onBlurCapture={event => { if (!event.currentTarget.contains(event.relatedTarget)) setFocused(false) }} inert={!present || undefined} aria-hidden={!present || undefined} initial={reduced ? false : { opacity: 0, x: 18, y: 4 }} animate={{ opacity: 1, x: 0, y: 0 }} exit={{ opacity: 0, x: reduced ? 0 : 12, transition: { duration: reduced ? 0 : motionTiming.exit } }} transition={{ duration: reduced ? 0 : motionTiming.content, ease: motionEase }}>{item.tone === 'success' ? <Check size={16} /> : item.tone === 'info' ? <Info size={16} /> : <AlertCircle size={16} />}<div className="toast-content"><span>{item.message}</span>{item.action && <Button variant="link" size="sm" onClick={() => { item.action?.run(); dismiss() }}>{item.action.label}</Button>}{item.details && <details className="operation-details" onToggle={event => setExpanded(event.currentTarget.open)}><summary>查看错误详情</summary><code>{item.details.code}</code>{item.details.requestId && <code>请求编号：{item.details.requestId}</code>}</details>}</div><Button variant="ghost" size="icon-xs" aria-label="关闭提示" onClick={dismiss}><X size={14} /></Button></m.div>
}
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const [hosts, setHosts] = useState<HTMLElement[]>([])
  const registerHost = useCallback((node: HTMLElement) => { setHosts(old => [...old, node]); return () => setHosts(old => old.filter(host => host !== node)) }, [])
  const host = hosts[hosts.length - 1]
  const [footerInset, setFooterInset] = useState(0)
  useEffect(() => {
    const footer = host?.querySelector<HTMLElement>('.dialog-footer')
    const measure = () => setFooterInset(footer?.getBoundingClientRect().height || 0)
    measure()
    if (!footer) return
    const observer = new ResizeObserver(measure); observer.observe(footer)
    return () => observer.disconnect()
  }, [host])
  const sequence = useRef(0)
  const notify: ToastFn = useCallback((message, tone = 'success', options = {}) => { const id = ++sequence.current; setItems(old => old.some(item => options.key ? item.key === options.key : item.message === message && item.tone === tone) ? old : [...old.slice(-2), { ...options, id, message, tone }]) }, [])
  return <ToastContext.Provider value={notify}><ToastHostContext.Provider value={registerHost}>{children}{createPortal(<div className="toasts" data-in-dialog={Boolean(host)} style={host ? { bottom: footerInset + 16 } : undefined} aria-live="polite" aria-label="操作提示"><AnimatePresence initial={false}>{items.map(item => <ToastMessage key={item.id} item={item} dismiss={() => setItems(old => old.filter(x => x.id !== item.id))} />)}</AnimatePresence></div>, host || document.body)}</ToastHostContext.Provider></ToastContext.Provider>
}
export function useToast() { return useContext(ToastContext) }
export function useErrorFeedback() {
  const toast = useToast()
  return useCallback((error: unknown, context: FeedbackContext, persist: (error: unknown) => void) => {
    if (feedbackPresentation(error, context) === 'card') persist(error)
    else toast(feedbackMessage(error, context), 'error', { details: feedbackDetails(error) })
  }, [toast])
}
