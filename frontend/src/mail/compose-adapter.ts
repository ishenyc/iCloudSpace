import { mailDraftPayload, validateMailDraft } from './draft-content.js'
import type { MailoutDraft } from '../control/mailout-contracts.ts'

export interface ComposerAttachment { key: string; filename: string; size: number; content_type: string; content_id: string; data: string }
export interface ComposerDraft { to: string; subject: string; text: string; body_format: 'text' | 'markdown' | 'html'; attachments: ComposerAttachment[] }

/** Preserve the mature draft normalization; only translate the HTTP shape. */
export function composerWireDraft(draft: ComposerDraft): MailoutDraft {
  const validation = validateMailDraft(draft)
  if (validation) throw new Error(validation)
  const payload = mailDraftPayload(draft, '')
  return { recipient: payload.to, subject: payload.subject, body: { format: payload.body_format, source: payload.text },
    attachments: payload.attachments.map((file: {filename:string;content_type:string;content_id?:string;data:string}) => ({
      filename: file.filename, media_type: file.content_type, content_id: file.content_id || '', inline: Boolean(file.content_id),
      bytes: Uint8Array.from(atob(file.data), character => character.charCodeAt(0)),
    })) }
}

/** Preview has no send eligibility check and does not upload attachment bytes. */
export function composerPreviewDraft(draft: ComposerDraft): MailoutDraft {
  return {recipient:'',subject:'',body:{format:draft.body_format,source:draft.text},attachments:[]}
}
