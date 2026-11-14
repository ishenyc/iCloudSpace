import type { InlineImageURL } from './public-client.ts'
import type { MailMetadata } from './contracts.ts'

export interface MailDocument { html: string; revoke(): void }

/** Only sanitized server HTML enters this inert template. The isolated frame
 * receives verified inert images, and cannot load network resources or scripts. */
export async function buildMailDocument(html: string, image: (cid: string) => Promise<InlineImageURL | null>): Promise<MailDocument> {
  const template = document.createElement('template')
  template.innerHTML = html
  const urls: InlineImageURL[] = [], resolved = new Map<string, InlineImageURL | null>()
  try {
    for (const node of template.content.querySelectorAll('img')) {
      const cid = node.getAttribute('src') || ''
      node.removeAttribute('src'); node.removeAttribute('srcset')
      if (!/^cid:/i.test(cid)) continue
      if (!resolved.has(cid)) {
        const item = await image(cid)
        resolved.set(cid, item)
        if (item) urls.push(item)
      }
      const item = resolved.get(cid)
      if (item) node.setAttribute('src', item.documentSource || item.url)
    }
    const policy = "default-src 'none'; img-src data: blob:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-src 'none'"
    let revoked = false
    return { html: `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${policy}"><meta name="referrer" content="no-referrer"><style>body{font:15px/1.6 system-ui,sans-serif;color:#222;padding:20px;overflow-wrap:anywhere}img{max-width:100%;height:auto}table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:7px 10px}pre{white-space:pre-wrap}</style></head><body>${template.innerHTML}</body></html>`,
      revoke() { if (!revoked) { revoked = true; for (const url of urls) url.revoke() } } }
  } catch (error) { for (const url of urls) url.revoke(); throw error }
}

export function formatMailTime(value?: string | null): string {
  if (!value) return '—'
  const time = new Date(value)
  return Number.isNaN(time.getTime()) ? '—' : time.toLocaleString('zh-CN', { hour12: false })
}

export function mailContentLabel(state: MailMetadata['raw_state']): string {
  return { staged: '正在归档', available: '原文可核验', evicted: '已按留存策略清理', missing: '原文缺失', corrupt: '原文校验异常', over_budget: '超出归档容量', metadata_only: '仅保留邮件信息' }[state]
}

export function formatMailSize(value: string): string {
  const bytes = Number(value)
  if (bytes < 1024) return value + ' 字节'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KiB'
  return (bytes / (1024 * 1024)).toFixed(1) + ' MiB'
}
