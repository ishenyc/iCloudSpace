import type { MailDownload } from './contracts.ts'

export async function saveMailDownload(download: MailDownload, filename: string): Promise<void> {
  const chunks: Uint8Array<ArrayBuffer>[] = [], reader = download.stream.getReader()
  let size = 0
  try {
    for (;;) {
      const part = await reader.read()
      if (part.done) break
      size += part.value.byteLength
      if (size > 100 * 1024 * 1024) throw new Error('此文件超出浏览器下载上限，请通过邮箱接口下载。')
      chunks.push(new Uint8Array(part.value))
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error }
  finally { reader.releaseLock() }
  const url = URL.createObjectURL(new Blob(chunks, { type: download.media_type }))
  const link = document.createElement('a')
  link.download = filename.replace(/[\\/\x00-\x1f]/g, '_') || 'mail.eml'
  link.href = url; link.rel = 'noopener noreferrer'
  document.body.append(link); link.click(); link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
