import { useEffect, useLayoutEffect, useRef, useState, type ClipboardEvent, type ReactNode } from 'react'
import { ArrowLeft, FileImage, Paperclip, Send, Eye, X, Mail, Check, Clock3, CircleAlert, LoaderCircle, Type, Bold, Italic, Heading2, List, Quote, Link, Code, Table2 } from 'lucide-react'
import { useControl } from '../lib/control'
import { AnimatePresence, AnimatedSection, useReducedMotion } from '../lib/motion'
import { Alert, Badge, Button, CopyButton, Field, Input, Modal, Select, Tabs, TabsContent, TabsList, TabsTrigger, Textarea } from '../components/ui'
import { Composition } from '../mail/composition'
import type { CompositionSnapshot } from '../mail/composition'
import { mailPreviewDocument, validateMailAttachments } from '../mail/draft-content.js'
import { composerWireDraft, composerPreviewDraft } from '../mail/compose-adapter'
import type { ComposerAttachment as Attachment, ComposerDraft as Draft } from '../mail/compose-adapter'
import type { MailoutDiagnostic } from '../control/mailout-contracts'
import { safeBrowserStorage } from '../control/client-state-handoff'
import { composerHasDraft, composerIssue, composerResult, type ComposerIssue } from '../mail/composer-presentation'

type Sender = { id: string; address: string }
const blankDraft = (): Draft => ({ to: '', subject: '', text: '', body_format: 'text', attachments: [] })
const sizeLabel = (size: number) => size >= 1024 * 1024 ? `${(size / 1024 / 1024).toFixed(2)} MiB` : size >= 1024 ? `${(size / 1024).toFixed(1)} KiB` : `${size} B`
const tools = [
  { label: '粗体', icon: Bold, md: ['**', '**'], html: ['<strong>', '</strong>'] },
  { label: '斜体', icon: Italic, md: ['*', '*'], html: ['<em>', '</em>'] },
  { label: '标题', icon: Heading2, md: ['\n## ', '\n'], html: ['<h2>', '</h2>'] },
  { label: '列表', icon: List, md: ['\n- ', '\n'], html: ['<ul><li>', '</li></ul>'] },
  { label: '引用', icon: Quote, md: ['\n> ', '\n'], html: ['<blockquote>', '</blockquote>'] },
  { label: '链接', icon: Link, md: ['[', '](https://example.com)'], html: ['<a href="https://example.com">', '</a>'] },
  { label: '代码', icon: Code, md: ['\n```\n', '\n```\n'], html: ['<pre><code>', '</code></pre>'] },
  { label: '表格', icon: Table2, md: ['\n| 标题 | 内容 |\n| --- | --- |\n| ', ' | 内容 |\n'], html: ['<table><tr><th>标题</th><th>内容</th></tr><tr><td>', '</td><td>内容</td></tr></table>'] },
]
function readBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result).split(',')[1] || '')
    reader.onerror = () => reject(new Error('文件读取失败，请重新选择。'))
    reader.readAsDataURL(file)
  })
}
function MailDiagnostic({ value }: { value: MailoutDiagnostic }) {
  return <dl><dt>阶段</dt><dd>{value.stage}</dd>{value.operation && <><dt>子操作</dt><dd>{value.operation}</dd></>}{value.kind && <><dt>原因</dt><dd>{value.kind}</dd></>}{value.attempts && <><dt>尝试次数</dt><dd>{value.attempts}</dd></>}{value.transport_phase && <><dt>传输阶段</dt><dd>{value.transport_phase}</dd></>}{value.transport_reason && <><dt>传输原因</dt><dd>{value.transport_reason}</dd></>}{value.http_status && <><dt>服务状态</dt><dd>{value.http_status}</dd></>}{value.provider_code && <><dt>服务代码</dt><dd>{value.provider_code}</dd></>}</dl>
}

/** Animate only explicit view changes. The fixed dialog itself never uses layout projection. */
function ComposerSurface({ view, children }: { view: string; children: ReactNode }) {
  const surface = useRef<HTMLDivElement>(null), content = useRef<HTMLDivElement>(null)
  const previous = useRef({ view, height: 0 }), animation = useRef<Animation | null>(null)
  const reduced = useReducedMotion()
  useLayoutEffect(() => {
    const outer = surface.current, inner = content.current
    if (!outer || !inner) return
    const padding = getComputedStyle(outer)
    const nextHeight = inner.getBoundingClientRect().height + parseFloat(padding.paddingTop) + parseFloat(padding.paddingBottom)
    const fromHeight = animation.current ? outer.getBoundingClientRect().height : previous.current.height
    animation.current?.cancel(); animation.current = null
    if (!reduced && previous.current.view !== view && fromHeight > 0 && Math.abs(fromHeight - nextHeight) > 1 && outer.animate) {
      const active = outer.animate([{ height: `${fromHeight}px` }, { height: `${nextHeight}px` }], { duration: 220, easing: 'cubic-bezier(.22,1,.36,1)' })
      animation.current = active
      active.onfinish = () => { if (animation.current === active) animation.current = null }
    }
    previous.current = { view, height: nextHeight }
  }, [view, reduced])
  useLayoutEffect(() => {
    if (!content.current || typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(([entry]) => {
      const padding = getComputedStyle(surface.current!)
      const height = entry.contentRect.height + parseFloat(padding.paddingTop) + parseFloat(padding.paddingBottom)
      // Resizing or revealing controls mid-transition should return to natural layout immediately.
      if (Math.abs(previous.current.height - height) > 1) { animation.current?.cancel(); animation.current = null }
      previous.current.height = height
    })
    observer.observe(content.current)
    return () => { observer.disconnect(); animation.current?.cancel() }
  }, [])
  return <div ref={surface} className="composer-surface"><div ref={content} className="composer">{children}</div></div>
}

export function MailComposer({ alias, onClose }: { alias: Sender; onClose: () => void }) {
  const { mailout, basePath } = useControl()
  const mounted = useRef(true)
  const [draft, setDraft] = useState<Draft>(blankDraft)
  const draftRef = useRef(draft); draftRef.current = draft
  const [receipt, setReceipt] = useState<CompositionSnapshot>({ contextKey: '', submissionKey: '', context: null, submission: null, pending: null, contextUncertain: false, submissionNotSent: false, error: null })
  const [composition] = useState(() => new Composition(mailout, basePath, alias.id, safeBrowserStorage(() => window.localStorage), state => { if (mounted.current) setReceipt(state) }))
  const [reading, setReading] = useState(false), [previewing, setPreviewing] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [preview, setPreview] = useState<{ html: string; text: string } | null>(null)
  const [previewTab, setPreviewTab] = useState('html')
  const [draftRetained, setDraftRetained] = useState(false)
  const [editingRetry, setEditingRetry] = useState(false), [formatOptions, setFormatOptions] = useState(false)
  const [issue, setIssue] = useState<ComposerIssue | null>(null)
  const [dragging, setDragging] = useState(false)
  const editor = useRef<HTMLTextAreaElement>(null), previewPanel = useRef<HTMLDivElement>(null)
  const recipientInput = useRef<HTMLInputElement>(null), subjectInput = useRef<HTMLInputElement>(null), resultPanel = useRef<HTMLElement>(null)
  const restoreEditorFocus = useRef(false)
  const filesInput = useRef<HTMLInputElement>(null), imagesInput = useRef<HTMLInputElement>(null)
  const editorActions = useRef<HTMLDivElement>(null)
  const focusAttachmentButton = () => editorActions.current?.querySelector<HTMLButtonElement>('[data-composer-attach]')?.focus()
  const readingRef = useRef(false), previewAbort = useRef<AbortController | null>(null)
  const busy = receipt.pending === 'send' || receipt.pending === 'context'
  const checking = receipt.pending === 'query'
  const submitted = Boolean(receipt.submissionKey), requestId = receipt.submissionKey
  const locked = busy || submitted && !editingRetry || reading || Boolean(receipt.recoveryBlocked)
  const showingResult = (submitted || Boolean(receipt.recoveryBlocked)) && !editingRetry
  const result = composerResult(receipt)
  const canNewDraft = composition.canStartAnother
  const hasUnsavedContent = receipt.submission?.outcome !== 'accepted' && composerHasDraft(draft)
  const [closing, setClosing] = useState(false)
  function requestClose() { if (hasUnsavedContent) setClosing(true); else onClose() }
  useEffect(() => {
    if (!hasUnsavedContent) return
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = '' }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [hasUnsavedContent])

  useEffect(() => {
    mounted.current = true
    void composition.recover()
    return () => { mounted.current = false; previewAbort.current?.abort() }
  }, [composition])

  useEffect(() => {
    if (!showingResult) return
    resultPanel.current?.focus()
  }, [showingResult])
  useEffect(() => {
    if (preview) previewPanel.current?.focus()
    else if (restoreEditorFocus.current) { editor.current?.focus(); restoreEditorFocus.current = false }
  }, [preview])
  function changeDraft(change: Partial<Draft>) { setDraft(current => ({ ...current, ...change })); setIssue(null) }

  function returnToEditor() {
    restoreEditorFocus.current = true; setPreview(null)
  }
  function insertAtCursor(prefix: string, suffix = '', placeholder = '内容', source = draftRef.current) {
    const start = editor.current?.selectionStart ?? source.text.length, end = editor.current?.selectionEnd ?? start
    const text = source.text.slice(start, end) || placeholder
    setDraft({ ...source, text: source.text.slice(0, start) + prefix + text + suffix + source.text.slice(end) })
    requestAnimationFrame(() => { editor.current?.focus(); editor.current?.setSelectionRange(start + prefix.length, start + prefix.length + text.length) })
  }
  async function addFiles(files: File[], inline = false) {
    if (locked || readingRef.current || !files.length) return
    const pending = files.map(file => ({ key: crypto.randomUUID(), filename: file.name, size: file.size,
      content_type: file.type.split(';')[0] || 'application/octet-stream', content_id: inline ? `img-${crypto.randomUUID()}@icloudspace.local` : '', file }))
    const invalid = validateMailAttachments([...draftRef.current.attachments, ...pending])
    if (invalid) { setError(new Error(invalid)); return }
    readingRef.current = true; setReading(true); setError(null); setIssue(null)
    try {
      const ready = await Promise.all(pending.map(async ({ file, ...entry }) => ({ ...entry, data: await readBase64(file) })))
      if (!mounted.current) return
      const next: Draft = { ...draftRef.current, attachments: [...draftRef.current.attachments, ...ready], body_format: inline && draftRef.current.body_format === 'text' ? 'markdown' : draftRef.current.body_format }
      if (inline) insertAtCursor(ready.map(file => next.body_format === 'html' ? '<p><img src="cid:' + file.content_id + '" alt="图片"></p>' : '\n![图片](cid:' + file.content_id + ')\n').join(''), '', '', next)
      else { setDraft(next); requestAnimationFrame(focusAttachmentButton) }
    } catch (failure) { if (mounted.current) setError(failure) }
    finally { readingRef.current = false; if (mounted.current) setReading(false) }
  }
  function pasteImages(event: ClipboardEvent<HTMLTextAreaElement>) {
    const images = Array.from(event.clipboardData.files).filter(file => file.type.startsWith('image/'))
    if (images.length && !locked) { event.preventDefault(); void addFiles(images, true) }
  }
  function removeAttachment(file: Attachment) {
    if (locked) return
    setIssue(null)
    focusAttachmentButton()
    setDraft(current => ({ ...current, attachments: current.attachments.filter(item => item.key !== file.key),
      text: file.content_id ? current.text.replaceAll('\n![图片](cid:' + file.content_id + ')\n', '').replaceAll('<p><img src="cid:' + file.content_id + '" alt="图片"></p>', '') : current.text }))
  }
  async function previewMail() {
    if (previewing || reading) return
    previewAbort.current?.abort()
    const controller = new AbortController(); previewAbort.current = controller
    setPreviewing(true); setError(null)
    const source = draftRef.current
    try {
      const response = await mailout.preview(alias.id, composerPreviewDraft(source), controller.signal)
      if (!mounted.current || controller.signal.aborted) return
      if (source.text !== draftRef.current.text || source.body_format !== draftRef.current.body_format) throw new Error('正文已改变，请重新预览。')
      setPreview({ html: mailPreviewDocument(response.result.html, source.attachments), text: response.result.text }); setPreviewTab(source.body_format === 'text' ? 'text' : 'html')
    } catch (failure) { if (mounted.current && !controller.signal.aborted) setError(failure) }
    finally { if (mounted.current) setPreviewing(false) }
  }
  async function sendDraft(retry = false) {
    if (readingRef.current || busy || checking || (submitted && !retry) || retry && (!composition.canRetry || !draftRetained)) return
    const validation = composerIssue(draftRef.current)
    if (validation) {
      setIssue(validation)
      if (preview) returnToEditor()
      requestAnimationFrame(() => (validation.field === 'to' ? recipientInput.current : validation.field === 'subject' ? subjectInput.current : editor.current)?.focus())
      return
    }
    setIssue(null); setEditingRetry(false); setPreview(null)
    setError(null)
    setDraftRetained(true)
    try { await composition.submit(composerWireDraft(draftRef.current), retry); if (mounted.current) setDraftRetained(Boolean(composition.snapshot.submissionKey)) }
    catch (failure) { if (mounted.current) setError(failure) }
  }
  async function checkResult() { await composition.querySubmission() }
  function newDraft() { if (composition.startAnother()) { setDraft(current => ({ ...blankDraft(), to: current.to })); setDraftRetained(false); setEditingRetry(false); setFormatOptions(false); setPreview(null); setIssue(null); setError(null); requestAnimationFrame(() => recipientInput.current?.focus()) } }

  const attachments = <div className="composer-file-list" aria-label="邮件附件"><AnimatePresence initial={false}>{draft.attachments.map(file => <AnimatedSection className="composer-file-motion" key={file.key} initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}><div className="composer-file">
    {file.content_id ? <img className="composer-thumbnail" src={`data:${file.content_type};base64,${file.data}`} alt="" /> : <Paperclip size={16} />}
    <span>{file.filename}<small>{sizeLabel(file.size)}{file.content_id ? ' · 正文图片' : ''}</small></span>
    {!preview && !showingResult && <Button size="icon-sm" variant="ghost" disabled={locked} aria-label={`移除 ${file.filename}`} onClick={() => removeAttachment(file)}><X size={14} /></Button>}
  </div></AnimatedSection>)}</AnimatePresence></div>

  return <Modal open onOpenChange={open => { if (!open && !busy && !reading) { if (preview) returnToEditor(); else requestClose() } }} title={showingResult ? '发送状态' : preview ? '预览邮件' : editingRetry ? '修改邮件' : '撰写邮件'} description={showingResult ? '查看这封邮件的处理结果' : '收件人将看到下方隐私邮箱作为发件人'} wide className="mail-composer-dialog" bodyClassName="mail-composer-body" footer={<>
    <div className="composer-footer-start">{preview ? <Button variant="ghost" onClick={returnToEditor}><ArrowLeft size={15} />继续编辑</Button> : <Button variant="ghost" disabled={busy || reading} onClick={requestClose}>{showingResult ? '关闭' : '取消'}</Button>}</div>
    <div className="composer-footer-actions">
      {showingResult ? <>
        {submitted && <Button variant={canNewDraft ? 'outline' : 'default'} disabled={busy || checking || closing} loading={checking} loadingLabel="正在查询…" onClick={() => void checkResult()}>查看发送结果</Button>}
        {canNewDraft && (composition.canRetry && draftRetained ? <Button disabled={closing} onClick={() => { setEditingRetry(true); setPreview(null); setError(null); requestAnimationFrame(() => recipientInput.current?.focus()) }}>修改后重试</Button> : <Button disabled={closing} onClick={newDraft}>写新邮件</Button>)}
      </> : <>
        {!preview && <Button variant="outline" disabled={reading || previewing || closing} loading={previewing} loadingLabel="生成预览…" onClick={() => void previewMail()}><Eye size={15} />预览</Button>}
        <Button className="composer-send-action" disabled={closing || busy || checking || reading || receipt.recoveryBlocked || editingRetry && !composition.canRetry} loading={busy} loadingLabel="正在发送…" onClick={() => void sendDraft(editingRetry)}><Send size={15} />{editingRetry ? '重新发送' : '发送邮件'}</Button>
      </>}
    </div>
  </>}>
    <ComposerSurface view={showingResult ? 'result' : preview ? 'preview' : 'writing'}>
      <div className="composer-sender"><Mail size={15} aria-hidden="true" /><span>发件人</span><strong>{alias.address}</strong><Badge>隐私邮箱</Badge></div>
      {closing && <Alert tone="warning" attention="focus" title="放弃这封草稿？" actions={<><Button size="sm" onClick={() => setClosing(false)}>{showingResult ? '返回发送状态' : '继续编辑'}</Button><Button size="sm" variant="outline" className="alert-discard-action" onClick={onClose}>放弃草稿</Button></>}>
        关闭后，当前草稿的收件人、正文和附件不会保留。{submitted && '已提交的发送记录仍可查询。'}
      </Alert>}

      {showingResult ? <div key="result" className="composer-result-view composer-view-enter">
        <section ref={resultPanel} tabIndex={-1} className="composer-result" data-tone={result.tone} aria-label="发送结果">
          <div className="composer-result-icon" aria-hidden="true"><span key={busy || checking ? 'busy' : result.tone} className="composer-status-symbol">{busy || checking ? <LoaderCircle className="animate-spin" size={24} /> : result.tone === 'success' ? <Check className="composer-success-check" size={24} /> : receipt.submission?.outcome === 'unknown' ? <Clock3 size={24} /> : <CircleAlert size={24} />}</span></div>
          <div role="status" aria-live="polite"><h3>{result.title}</h3><p>{result.detail}</p></div>
        </section>
        {draftRetained && <div className="composer-envelope"><dl><dt>收件人</dt><dd>{draft.to}</dd><dt>主题</dt><dd>{draft.subject}</dd></dl>{draft.attachments.length > 0 && <p>{draft.attachments.length} 个附件 · {sizeLabel(draft.attachments.reduce((sum, file) => sum + file.size, 0))}</p>}</div>}
        {composition.canRetry && draftRetained && <p className="composer-help">草稿和附件仍在当前窗口。你可以先修改内容，再重新发送。</p>}
        {!draftRetained && !busy && <p className="composer-help">这是上次发送的记录。为保护隐私，正文和附件未保存在浏览器中。</p>}
      </div> : preview ? <div key="preview" ref={previewPanel} className="composer-preview composer-view-enter" tabIndex={-1} role="region" aria-label="邮件预览">
        <div className="composer-envelope"><dl><dt>收件人</dt><dd>{draft.to || '尚未填写'}</dd><dt>主题</dt><dd>{draft.subject || '尚未填写'}</dd></dl></div>
        <Tabs value={previewTab} onValueChange={setPreviewTab}>
          <TabsList aria-label="预览格式"><TabsTrigger value="html">邮件效果</TabsTrigger><TabsTrigger value="text">纯文本</TabsTrigger></TabsList>
          <TabsContent value="html"><iframe title="邮件正文隔离预览" sandbox="" referrerPolicy="no-referrer" srcDoc={preview.html} /></TabsContent>
          <TabsContent value="text"><pre>{preview.text || '（无正文）'}</pre></TabsContent>
        </Tabs>
        {attachments}<p className="composer-help">预览不会发送邮件；外部图片不加载。</p>
      </div> : <div key="writing" className="composer-writing composer-view-enter">
        {editingRetry && <div className="composer-retry-note">上次邮件未发送成功。修改后点击「重新发送」才会提交新请求。</div>}
        <div className="composer-header-fields">
          <Field label="收件人" description={issue?.field === 'to' && <span className="composer-field-error" role="alert">{issue.message}</span>}><Input ref={recipientInput} type="email" autoComplete="off" value={draft.to} disabled={locked} aria-invalid={issue?.field === 'to'} placeholder="填写对方的邮箱地址" onChange={event => changeDraft({ to: event.target.value })} /></Field>
          <Field label="主题" description={issue?.field === 'subject' && <span className="composer-field-error" role="alert">{issue.message}</span>}><Input ref={subjectInput} value={draft.subject} maxLength={998} disabled={locked} aria-invalid={issue?.field === 'subject'} placeholder="为这封邮件写个主题" onChange={event => changeDraft({ subject: event.target.value })} /></Field>
        </div>
        <div className="composer-paper" data-dragging={dragging} onDragOver={event => { if (event.dataTransfer.types.includes('Files')) { event.preventDefault(); if (!locked) setDragging(true) } }} onDragLeave={event => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false) }} onDrop={event => { event.preventDefault(); setDragging(false); if (!locked) void addFiles(Array.from(event.dataTransfer.files)) }}>
          <div ref={editorActions} className="composer-editor-actions">
            <Button data-composer-attach variant="ghost" size="sm" disabled={locked} onClick={() => filesInput.current?.click()}><Paperclip size={15} />{reading ? '读取中…' : '附件'}</Button>
            <Button variant="ghost" size="sm" disabled={locked} onClick={() => imagesInput.current?.click()}><FileImage size={15} />图片</Button>
            <Button className="composer-format-toggle" variant="ghost" size="sm" aria-expanded={formatOptions} aria-controls="composer-format-options" disabled={locked} onClick={() => setFormatOptions(value => !value)}><Type size={15} />{draft.body_format === 'text' ? '格式选项' : draft.body_format === 'markdown' ? 'Markdown' : 'HTML 源码'}</Button>
          </div>
          <div id="composer-format-options" className="composer-format-reveal" data-open={formatOptions} inert={!formatOptions} aria-hidden={!formatOptions}><div><div className="composer-format-options"><Select aria-label="正文格式" value={draft.body_format} disabled={locked || !formatOptions} onChange={event => changeDraft({ body_format: event.target.value as Draft['body_format'] })}><option value="text">纯文本</option><option value="markdown">Markdown 排版</option><option value="html">HTML 源码</option></Select><span>{draft.body_format === 'text' ? '直接输入文字即可。排版和源码格式可按需选择。' : '这里编辑的是格式标记，点击预览查看收件人看到的效果。'}</span></div></div></div>
          {draft.body_format !== 'text' && <div className="composer-format-tools" role="group" aria-label="正文格式工具">{tools.map(tool => <Button key={tool.label} size="icon-sm" variant="ghost" title={tool.label} aria-label={tool.label} disabled={locked} onMouseDown={event => event.preventDefault()} onClick={() => { const [prefix, suffix] = draft.body_format === 'html' ? tool.html : tool.md; insertAtCursor(prefix, suffix) }}><tool.icon size={15} /></Button>)}<span className="composer-help">选中文字后设置格式</span></div>}
          <Textarea ref={editor} aria-label={draft.body_format === 'html' ? 'HTML 正文源码' : '正文'} aria-invalid={issue?.field === 'body'} aria-describedby={issue?.field === 'body' ? 'composer-body-error' : undefined} rows={9} value={draft.text} disabled={locked} placeholder="在这里写下你想说的话…" className={draft.body_format === 'html' ? 'composer-body-input mono' : 'composer-body-input'} onChange={event => changeDraft({ text: event.target.value })} onPaste={pasteImages} />
          {issue?.field === 'body' && <p id="composer-body-error" className="composer-field-error" role="alert">{issue.message}</p>}
          {dragging && <div className="composer-drop-hint">松开即可添加附件</div>}
          {attachments}
          <div className="composer-writing-hint"><span>{draft.attachments.length ? `${draft.attachments.length} / 10 个附件 · ${sizeLabel(draft.attachments.reduce((sum, file) => sum + file.size, 0))} / 10 MiB` : '可拖入文件，或粘贴图片'}</span><span>{draft.text.length.toLocaleString()} 字符</span></div>
        </div>
        {issue?.field === 'attachments' && <Alert tone="warning" attention="focus">{issue.message}</Alert>}
        <input ref={filesInput} hidden type="file" multiple disabled={locked} onChange={event => { void addFiles(Array.from(event.target.files || [])); event.target.value = '' }} />
        <input ref={imagesInput} hidden type="file" multiple accept="image/png,image/jpeg,image/gif,image/webp" disabled={locked} onChange={event => { setFormatOptions(true); void addFiles(Array.from(event.target.files || []), true); event.target.value = '' }} />
        <p className="composer-help composer-draft-note">草稿仅保留在当前窗口，关闭前请确认内容。</p>
      </div>}

      {Boolean(error || receipt.error) && <Alert error={error || receipt.error} attention="focus" />}
      {receipt.recoveryBlocked && <Alert tone="warning"><div className="stack"><span>请保留浏览器数据；恢复存储访问后重新打开。现在仅可查询原结果。</span>{receipt.recoveryKeys?.map(key => <div key={key} className="stack"><code className="mono break-all">{key}</code><div className="row-actions"><CopyButton value={key} label="复制原发送编号" /><Button variant="outline" disabled={Boolean(receipt.pending)} onClick={() => void composition.querySubmission(key)}>查询此原发送结果</Button></div></div>)}{receipt.recoveryContextKeys?.map(key => <div key={'context:' + key} className="stack"><code className="mono break-all">{key}</code><div className="row-actions"><CopyButton value={key} label="复制原准备编号" /><Button variant="outline" disabled={Boolean(receipt.pending)} onClick={() => void composition.readContext(false, key)}>查询此原准备结果</Button></div></div>)}</div></Alert>}
      {submitted && <details className="operation-details composer-operation"><summary>发送记录与技术详情</summary><div className="stack"><code className="mono break-all">{requestId}</code><CopyButton value={requestId} label="复制发送编号" /><p>此编号用于查询原结果。结果未知时不会自动重发；关闭后可以重新打开此邮箱的撰写窗口查看。</p>{receipt.submission?.code && <p>{receipt.submission.code}</p>}{receipt.submission?.diagnostic && <MailDiagnostic value={receipt.submission.diagnostic} />}</div></details>}
      {receipt.contextKey && !submitted && <details className="operation-details composer-operation"><summary>此前的准备记录</summary><div className="stack"><p>查看历史准备结果，不会发送邮件。</p><Button variant="outline" disabled={!!receipt.pending} onClick={() => void composition.readContext(false)}>查看原准备结果</Button><code className="mono break-all">{receipt.contextKey}</code>{receipt.context?.code && <p>{receipt.context.code}</p>}{receipt.context?.diagnostic && <MailDiagnostic value={receipt.context.diagnostic} />}</div></details>}
    </ComposerSurface>
  </Modal>
}
