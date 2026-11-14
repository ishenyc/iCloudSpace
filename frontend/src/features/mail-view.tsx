import { useEffect, useRef, useState } from 'react'
import { ArrowLeft, Download, Paperclip } from 'lucide-react'
import { useControl } from '../lib/control'
import { useResource } from '../lib/hooks'
import { Alert, Badge, Button, CopyButton, Empty, Loading, Sheet, Tabs, TabsContent, TabsList, TabsTrigger, useErrorFeedback } from '../components/ui'
import { RefreshButton } from '../components/refresh-button'
import { buildMailDocument, formatMailTime, formatMailSize, mailContentLabel } from '../mail/display'
import { saveMailDownload } from '../mail/download'
import { createInlineImageURL } from '../mail/public-client'
import type { MailDocument } from '../mail/display'
import type { MailPageQuery } from '../mail/contracts'
import { HttpError } from '../transport/errors'

/** Operator viewing has no public credential reveal, consume or Seen mutation. */
export function MailViewer({ addressID, address, archived = false, onClose }: { addressID: string; address: string; archived?: boolean; onClose: () => void }) {
  const { mail } = useControl(), reportError = useErrorFeedback()
  const [cursor, setCursor] = useState<MailPageQuery>({ limit: 20 })
  const [pages, setPages] = useState<MailPageQuery[]>([])
  const [uid, setUID] = useState<number | null>(null)
  const [showList, setShowList] = useState(false)
  const [tab, setTab] = useState('html')
  const [documentHTML, setDocumentHTML] = useState<string | null>(null)
  const [frameError, setFrameError] = useState<unknown>(null)
  const [downloadError, setDownloadError] = useState<unknown>(null)
  const [downloading, setDownloading] = useState(false)
  const downloads = useRef<AbortController | null>(null)
  const mounted = useRef(true)
  const historyList = useRef<HTMLDivElement | null>(null)
  const messageContent = useRef<HTMLDivElement | null>(null)
  const history = useResource(signal => mail.messages(addressID, cursor, signal).then(response => response.result), [addressID, cursor.before_time, cursor.before_id], { keepPreviousData: true })
  const codes = useResource(signal => mail.codes(addressID, 100, signal).then(response => response.result), [addressID], { poll: false })
  const message = useResource(signal => archived && uid === null ? Promise.resolve(null) : uid === null ? mail.latest(addressID, signal).then(response => response.result.message).catch(error => {
    if (error instanceof HttpError && error.status === 404 && error.code === 'MAIL_NOT_FOUND') return null
    throw error
  }) : mail.message(addressID, uid, signal).then(response => response.result), [addressID, uid, archived])
  const firstHistoryUID = history.data?.items.find(item => item.uid !== null)?.uid ?? null
  useEffect(() => {
    if (archived && uid === null && firstHistoryUID !== null && !history.loading && !history.stale && !history.error) setUID(firstHistoryUID)
  }, [archived, uid, firstHistoryUID, history.loading, history.stale, history.error])
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; downloads.current?.abort() } }, [])
  useEffect(() => { if (historyList.current) historyList.current.scrollTop = 0 }, [addressID, cursor.before_time, cursor.before_id])
  useEffect(() => { if (messageContent.current) messageContent.current.scrollTop = 0 }, [addressID, uid, tab])
  useEffect(() => {
    let active = true, frame: MailDocument | null = null
    const controller = new AbortController()
    setDocumentHTML(null); setFrameError(null)
    const current = message.data
    if (current) void buildMailDocument(current.html, cid => current.metadata.uid === null ? Promise.resolve(null) : createInlineImageURL(cid, current.attachments, part => mail.attachment(addressID, current.metadata.uid!, part, controller.signal), 10 << 20, { opaqueDocument: true })).then(result => {
      frame = result
      if (active) setDocumentHTML(result.html)
      else result.revoke()
    }).catch(error => { if (active) setFrameError(error) })
    return () => { active = false; controller.abort(); frame?.revoke() }
  }, [mail, addressID, message.data])
  async function download(part?: string, filename?: string) {
    if (downloading) return
    const selected = message.data?.metadata.uid
    if (selected === null || selected === undefined) return
    const controller = new AbortController(); downloads.current = controller
    setDownloading(true); setDownloadError(null)
    try {
      const file = part ? await mail.attachment(addressID, selected, part, controller.signal) : await mail.raw(addressID, selected, { signal: controller.signal })
      await saveMailDownload(file, filename || 'mail-' + selected + '.eml')
    } catch (error) { if (mounted.current && !controller.signal.aborted) reportError(error, 'read', setDownloadError) }
    finally { if (mounted.current) setDownloading(false) }
  }
  const current = message.data
  const code = codes.data?.find(item => item.uid === current?.metadata.uid)?.code
  const hasHistory = Boolean(history.data?.items.length || pages.length)
  const error = downloadError || frameError || message.error || history.error || codes.error
  const selectingArchived = archived && uid === null && firstHistoryUID !== null && !history.error
  const reading = message.loading || selectingArchived || archived && history.loading && !current
  const empty = !history.loading && !history.stale && !message.loading && !current && !hasHistory && !error
  const listOpen = hasHistory && showList
  async function refresh() {
    await Promise.all([message.refresh(), history.refresh(), ...(codes.error ? [codes.refresh()] : [])])
  }
  function selectMessage(selected: number) { setUID(selected); setTab('html'); setShowList(false); setDownloadError(null) }
  return <Sheet open wide className="mail-reader-sheet" bodyClassName="mail-reader-body" title={archived ? '归档历史邮件' : '查看邮件'} description={address} onOpenChange={open => { if (!open) onClose() }} footer={<><Button variant="secondary" onClick={onClose}>关闭</Button><RefreshButton variant="secondary" pending={message.refreshing || history.refreshing || codes.manualRefreshing} onRefresh={refresh}>刷新</RefreshButton></>}>
    <div className="stack mailbox-detail" data-history={hasHistory} data-empty={empty} data-list-open={listOpen}>
      <div className="mail-reader-toolbar"><p className="section-note">{archived ? '归档后已保存的历史内容仍可查看。' : ''}查看与下载不会消费邮件或标记已读。</p>
        {hasHistory && <Button variant="secondary" size="sm" className="mail-history-toggle" aria-expanded={listOpen} onClick={() => setShowList(!showList)}>{listOpen ? '返回邮件正文' : '查看历史目录'}</Button>}
      </div>
      {error ? <Alert error={error}><RefreshButton variant="outline" size="sm" pending={message.refreshing || history.refreshing || codes.manualRefreshing} onRefresh={refresh}>重新读取</RefreshButton></Alert> : null}
      {(current || !archived && uid !== null) && <div className="detail-primary-actions mail-reader-actions">{!archived && <Button variant={uid === null ? 'default' : 'secondary'} onClick={() => { setUID(null); setTab('html'); setShowList(false); setDownloadError(null) }}>最新邮件</Button>}{current?.metadata.uid != null && <Button variant="secondary" disabled={downloading || current.metadata.raw_state !== 'available'} onClick={() => void download()}><Download size={14} />下载原始邮件</Button>}</div>}
      <div className="mail-reader-layout" data-history={hasHistory} data-empty={empty} data-list-open={listOpen}>
      {hasHistory && <section className="mail-reader-history" aria-label="历史邮件目录">
        <header className="mail-history-header"><h3>历史邮件</h3>{history.refreshing && <small className="text-muted">正在更新…</small>}</header>
        <div ref={historyList} className="stack mail-history-list">{history.data?.items.length ? history.data.items.map(item => <Button key={item.entry_id} title={item.subject || '无主题'} aria-pressed={current?.metadata.uid === item.uid} variant={current?.metadata.uid === item.uid ? 'secondary' : 'ghost'} className="mail-history-item" disabled={history.stale || item.uid === null} onClick={() => { if (item.uid !== null) selectMessage(item.uid) }}><span><span className="mail-history-subject" title={item.subject || '无主题'}>{item.subject || '无主题'}</span><small className="mail-history-meta"><time>{formatMailTime(item.received_at)}</time><span>{item.seen ? '已取件' : '未取件'}</span></small></span></Button>) : history.loading ? <Loading label="正在读取邮件目录" /> : !history.error ? <p className="text-muted">本页没有历史条目，可返回上一页查看。</p> : null}</div>
        <footer className="toolbar mail-history-pagination"><Button variant="secondary" size="sm" disabled={!pages.length || history.loading} onClick={() => { setCursor(pages[pages.length - 1]); setPages(pages.slice(0, -1)) }}><ArrowLeft size={14} />上一页</Button><Button variant="secondary" size="sm" disabled={!history.data?.more || history.loading || history.stale} onClick={() => { if (history.data?.next_time && history.data.next_id) { setPages([...pages, cursor]); setCursor({ limit: 20, before_time: history.data.next_time, before_id: history.data.next_id }) } }}>更早邮件</Button></footer>
      </section>}
      <div ref={messageContent} className="stack mail-reader-content" role="region" aria-label="邮件正文" tabIndex={0}>{reading ? <Loading label={archived && !hasHistory ? '正在读取历史目录' : '正在读取正文'} /> : current ? <><section className="detail-section"><div className="detail-section-heading"><h3>{current.metadata.subject || '无主题'}</h3><Badge>{current.metadata.seen ? '已取件' : '未取件'}</Badge></div><dl className="detail-list"><dt>发件人</dt><dd>{current.metadata.from.map(sender => sender.name ? sender.name + ' <' + sender.address + '>' : sender.address).join(', ') || '—'}</dd><dt>收件人</dt><dd>{current.metadata.to.map(receiver => receiver.address).join(', ') || address}</dd><dt>收件时间</dt><dd>{formatMailTime(current.metadata.received_at)}</dd><dt>原始内容</dt><dd>{mailContentLabel(current.metadata.raw_state)}</dd></dl></section>
        <div className="notice toolbar" aria-label="本封邮件验证码"><span className="text-muted">验证码</span>{code ? <><strong className="font-mono text-lg tracking-widest">{code}</strong><CopyButton value={code} label="复制验证码" /></> : <span>{codes.loading ? '读取中…' : '本封未提取到验证码'}</span>}</div>
        {!current.body_complete && <Alert tone="warning">当前保存的正文不完整。原始邮件可用时，可以下载核对。</Alert>}
        <Tabs value={tab} onValueChange={setTab}><TabsList><TabsTrigger value="html">格式化正文</TabsTrigger><TabsTrigger value="text">纯文本</TabsTrigger></TabsList><TabsContent value="html">{documentHTML ? <iframe title="邮件正文" sandbox="" referrerPolicy="no-referrer" srcDoc={documentHTML} className="min-h-[40vh] w-full rounded-lg border bg-white" /> : frameError ? <p className="text-muted">格式化正文未能打开，可切换纯文本或重新读取。</p> : <Loading label="正在准备隔离正文" />}</TabsContent><TabsContent value="text"><pre className="whitespace-pre-wrap break-words">{current.text || '无纯文本正文'}</pre></TabsContent></Tabs>
        {current.attachments.length > 0 && <section className="detail-section"><h3>附件</h3><div className="stack">{current.attachments.map(part => <Button variant="secondary" className="mail-attachment" key={part.part} disabled={downloading || !part.complete || current.metadata.uid === null || current.metadata.raw_state !== 'available'} onClick={() => void download(part.part || 'root', part.filename || 'attachment')}><Paperclip size={14} /><span className="truncate" title={part.filename || '未命名附件'}>{part.filename || '未命名附件'}</span><small title={part.byte_size + ' 字节'}>{formatMailSize(part.byte_size)}</small></Button>)}</div></section>}
      </> : empty ? <div className="mail-reader-empty"><Empty title={archived ? '没有保留的历史邮件' : '当前没有可展示的邮件'} description={archived ? '此邮箱已归档，当前没有保留的历史邮件。' : '同步完成后可刷新查看。查看不会消费邮件或标记已读。'} /></div> : !error && hasHistory ? <Empty compact title={archived ? '请选择历史邮件' : '查看已同步邮件'} description="从历史目录选择一封邮件，或直接打开最近一封。" action={firstHistoryUID !== null && <Button variant="secondary" disabled={history.stale} onClick={() => selectMessage(firstHistoryUID)}>查看最近一封邮件</Button>} /> : !error && history.loading ? <Loading label="正在读取邮件目录" /> : null}</div></div>
    </div>
  </Sheet>
}
