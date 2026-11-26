import { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Download, LoaderCircle, Moon, Paperclip, RefreshCw, Sun } from 'lucide-react'
import { HttpError } from './transport/errors'
import { openPublicViewer } from './mail/public-viewer'
import type { PublicViewerModel } from './mail/public-viewer'
import type { MailDocument } from './mail/display'
import type { MailMessage, MailPage, MailPageQuery } from './mail/contracts'
import { buildMailDocument, formatMailTime, formatMailSize, mailContentLabel } from './mail/display'
import { createInlineImageURL } from './mail/public-client'
import { saveMailDownload } from './mail/download'
import './styles.css'
import './public-view.css'

function failure(error: unknown): string {
  if (error instanceof HttpError && (error.status === 401 || error.status === 403)) return '访问授权已失效或不包含原文权限。请向提供方领取新的原文访问链接。'
  return '当前内容无法完整读取。可重新选择邮件，或稍后手动刷新。'
}

function PublicViewer({ model }: { model: PublicViewerModel }) {
  const [page, setPage] = useState<MailPage | null>(null), [query, setQuery] = useState<MailPageQuery>({}), [previous, setPrevious] = useState<MailPageQuery[]>([])
  const [message, setMessage] = useState<MailMessage | null>(null), [error, setError] = useState(''), [loading, setLoading] = useState(false), [reload, setReload] = useState(0)
  const [selected, setSelected] = useState<number | null>(null), [tab, setTab] = useState<'html' | 'text'>('html'), [documentHTML, setDocumentHTML] = useState(''), [downloadPart, setDownloadPart] = useState<string | null>(null)
  const downloading = downloadPart !== null
  const [theme, setTheme] = useState(() => matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
  useEffect(() => { document.documentElement.dataset.theme = theme; document.documentElement.classList.toggle('dark', theme === 'dark') }, [theme])
  useEffect(() => {
    const controller = new AbortController(); let active = true
    setLoading(true); setError(''); setMessage(null)
    void model.candidates(query, controller.signal).then(async next => {
      if (!active) return
      setPage(next)
      const result = selected === null ? await model.latest(next, controller.signal) : { message: await model.message(selected, controller.signal) }
      if (active) setMessage(result.message)
    }).catch(e => { if (active && !controller.signal.aborted) setError(failure(e)) }).finally(() => { if (active) setLoading(false) })
    return () => { active = false; controller.abort() }
  }, [model, query, selected, reload])
  useEffect(() => {
    const controller = new AbortController(); let active = true, frame: MailDocument | null = null
    setDocumentHTML('')
    if (message?.metadata.uid != null) {
      const current = message
      void buildMailDocument(current.html, cid => createInlineImageURL(cid, current.attachments, part => model.attachment(current.metadata.uid!, part, controller.signal), 10 << 20, { opaqueDocument: true }))
        .then(result => { frame = result; if (active) setDocumentHTML(result.html); else result.revoke() })
        .catch(e => { if (active && !controller.signal.aborted) setError(failure(e)) })
    }
    return () => { active = false; controller.abort(); frame?.revoke() }
  }, [model, message])
  async function download(part?: string, filename?: string) {
    const uid = message?.metadata.uid
    if (uid == null || downloading) return
    setDownloadPart(part ?? ''); setError('')
    try { await saveMailDownload(part ? await model.attachment(uid, part) : await model.raw(uid), filename || 'mail-' + uid + '.eml') }
    catch (e) { setError(failure(e)) }
    finally { setDownloadPart(null) }
  }
  return <main className="public-mail"><header className="public-mail-heading"><div><small>iCloudSpace</small><h1>邮件原文</h1><p>查看与下载不会消费邮件或标记已读。</p></div><button type="button" className="public-mail-icon" aria-label={theme === 'dark' ? '切换浅色' : '切换深色'} onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>{theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}</button></header>
    {error && <p role="alert" className="public-mail-alert">{error}</p>}
    <div className="public-mail-grid"><aside className="public-mail-card"><div className="public-mail-section-heading"><h2>原文目录</h2><button type="button" className="public-mail-icon" aria-label="手动刷新目录" aria-busy={loading} disabled={loading} onClick={() => setReload(reload + 1)}><RefreshCw size={15} className={loading ? 'spin' : undefined} /></button></div>
      <div className="public-mail-list">{page?.items.map(item => <button type="button" key={item.entry_id} disabled={loading || item.raw_state !== 'available'} data-selected={message?.metadata.uid === item.uid} onClick={() => { setSelected(item.uid); setTab('html') }}><strong>{item.subject || '无主题'}</strong><span>{formatMailTime(item.received_at)}</span><small>UID {item.uid} · {mailContentLabel(item.raw_state)}</small></button>)}</div>
      {!loading && !error && !page?.items.length && <p className="public-mail-empty">当前没有原文条目。</p>}
      <div className="public-mail-paging"><button type="button" disabled={loading || previous.length === 0} onClick={() => { setQuery(previous[previous.length - 1]); setPrevious(previous.slice(0, -1)); setSelected(null) }}>上一页</button><button type="button" disabled={loading || !page?.more} onClick={() => { if (page?.next_time && page.next_id) { setPrevious([...previous, query]); setQuery({ before_time: page.next_time, before_id: page.next_id }); setSelected(null) } }}>更早邮件</button></div></aside>
      <section className="public-mail-card public-mail-content" aria-busy={loading}>{loading ? <p className="public-mail-empty request-progress" role="status"><LoaderCircle className="spin" size={15} aria-hidden="true" />正在核验原文…</p> : message ? <><div className="public-mail-section-heading"><h2>{message.metadata.subject || '无主题'}</h2><button type="button" disabled={downloading} onClick={() => void download()}>{downloadPart === '' ? <><LoaderCircle size={14} className="spin" />正在下载…</> : <><Download size={14} />下载 .eml</>}</button></div><dl><dt>发件人</dt><dd>{message.metadata.from.map(m => m.name ? m.name + ' <' + m.address + '>' : m.address).join(', ') || '—'}</dd><dt>收件人</dt><dd>{message.metadata.to.map(m => m.address).join(', ') || '—'}</dd><dt>收件时间</dt><dd>{formatMailTime(message.metadata.received_at)}</dd><dt>本地 UID</dt><dd>{message.metadata.uid}</dd></dl>
        {!message.body_complete && <p role="status" className="public-mail-alert">显示正文不完整；可下载已核验的原始邮件查看。</p>}
        <div className="public-mail-tabs" role="tablist" aria-label="正文格式"><button type="button" role="tab" aria-selected={tab === 'html'} onClick={() => setTab('html')}>格式化正文</button><button type="button" role="tab" aria-selected={tab === 'text'} onClick={() => setTab('text')}>纯文本</button></div>
        {tab === 'html' ? documentHTML ? <iframe title="隔离邮件正文" sandbox="" referrerPolicy="no-referrer" srcDoc={documentHTML} /> : error ? null : <p className="public-mail-empty request-progress" role="status"><LoaderCircle className="spin" size={15} />正在准备正文…</p> : <pre>{message.text || '无纯文本正文'}</pre>}
        {message.attachments.length > 0 && <div className="public-mail-attachments"><h3>附件</h3>{message.attachments.map(part => <button type="button" key={part.part} disabled={downloading || !part.complete} onClick={() => void download(part.part || 'root', part.filename || 'attachment')}>{downloadPart === (part.part || 'root') ? <LoaderCircle size={14} className="spin" /> : <Paperclip size={14} />}<span>{part.filename || '未命名附件'}</span><small title={part.byte_size + ' 字节'}>{formatMailSize(part.byte_size)}</small></button>)}</div>}
      </> : error ? null : <p className="public-mail-empty">{page?.more ? '当前页没有可展示的完整原文，可查看更早邮件。' : '当前目录没有可展示的原文。'}</p>}</section></div>
    <footer>授权仅保存在当前页面内存中。关闭页面后需重新打开有效链接。<a href="/docs">公开接口文档</a></footer>
  </main>
}

const root = document.getElementById('public-viewer')
if (root) {
  try {
    const model = openPublicViewer(document.getElementById('space-public-viewer')?.textContent || '', location, history)
    createRoot(root).render(<PublicViewer model={model} />)
  } catch { root.textContent = '原文访问链接无效或缺少授权。请向提供方领取有效链接。' }
}
