import { InvalidResponseError, TransportError } from '../transport/index.ts'
import type { RequestContext } from '../transport/index.ts'

/** Six bytes, or an explicit empty result. Never decode an error page as OTP. */
export async function readCodeText(response: Response, context: RequestContext, signal?: AbortSignal): Promise<string | null> {
  if (response.status === 204) return null
  if (response.status !== 200 || response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'text/plain' || !response.body) {
    try { await response.body?.cancel() } catch { /* One response only. */ }
    throw new InvalidResponseError('invalid_code_text', context)
  }
  const reader = response.body.getReader(), bytes = new Uint8Array(6); let size = 0
  try {
    for (;;) {
      const chunk = await reader.read()
      if (chunk.done) break
      if (size + chunk.value.length > 6) throw new InvalidResponseError('invalid_code_text', context)
      bytes.set(chunk.value, size); size += chunk.value.length
    }
    if (size !== 6 || bytes.some(byte => byte < 48 || byte > 57)) throw new InvalidResponseError('invalid_code_text', context)
    return String.fromCharCode(...bytes)
  } catch (error) {
    try { await reader.cancel() } catch { /* No retry. */ }
    if (error instanceof InvalidResponseError) throw error
    throw new TransportError(signal?.aborted ? 'aborted' : 'body_read', context)
  } finally { reader.releaseLock() }
}
