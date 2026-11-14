// Mail draft validation and composition. Protocol and storage adapters are separate.
export function validateMailDraft(draft) {
  const to = String(draft.to || "").trim();
  if (!/^[^\s@<>,;]+@[^\s@<>,;]+\.[^\s@<>,;]+$/.test(to)) return "请填写一个有效的收件邮箱地址。";
  if (!draft.subject?.trim() || /[\r\n\x00-\x1f\x7f]/.test(draft.subject) || new TextEncoder().encode(draft.subject.trim()).length > 998) return "请填写有效主题，且不要包含换行。";
  if (!["", "text", "markdown", "html"].includes(draft.body_format || "")) return "请选择有效的正文格式。";
  if ((!draft.text?.trim() && !draft.attachments?.length) || String(draft.text || "").includes("\0") || new TextEncoder().encode(draft.text || "").length > 100 * 1024) return "请填写正文或添加附件；正文最多 100 KiB。";
  const attachmentsError = validateMailAttachments(draft.attachments || []);
  if (attachmentsError) return attachmentsError;
  return "";
}

export const MAX_MAIL_ATTACHMENT_BYTES = 10 * 1024 * 1024;
export const MAX_MAIL_ATTACHMENTS = 10;
const inlineImageTypes = new Set(["image/png", "image/jpeg", "image/gif", "image/webp"]);

export function mailAttachmentSize(file) {
  if (Number.isSafeInteger(file.size) && file.size >= 0) return file.size;
  const data = String(file.data || "");
  return Math.max(0, Math.floor(data.length * 3 / 4) - (data.endsWith("==") ? 2 : data.endsWith("=") ? 1 : 0));
}

export function validateMailAttachments(files) {
  if (files.length > MAX_MAIL_ATTACHMENTS) return "附件最多 10 个。";
  let total = 0;
  const ids = new Set();
  for (const file of files) {
    const name = String(file.filename || file.name || "").trim();
    if (!name || [".", ".."].includes(name) || /[\\/\x00-\x1f\x7f]/.test(name) || new TextEncoder().encode(name).length > 255) return "附件文件名无效，不能包含路径或控制字符。";
    total += mailAttachmentSize(file);
    if (total > MAX_MAIL_ATTACHMENT_BYTES) return "附件总大小不能超过 10 MiB。";
    if (file.content_id) {
      if (!inlineImageTypes.has(file.content_type)) return "正文图片仅支持 PNG、JPEG、GIF 或 WebP。";
      if (ids.has(file.content_id)) return "正文图片标识重复。";
      ids.add(file.content_id);
    }
  }
  return "";
}

export function mailDraftPayload(draft, requestId) {
  return {
    request_id: requestId, to: draft.to.trim(), subject: draft.subject.trim(), text: draft.text || "",
    body_format: draft.body_format || "text",
    attachments: (draft.attachments || []).map(file => ({
      filename: file.filename.trim(), content_type: file.content_type, data: file.data,
      ...(file.content_id ? { content_id: file.content_id } : {}),
    })),
  };
}

export function mailPreviewDocument(html, attachments = []) {
  const images = new Map(attachments.filter(file => file.content_id && inlineImageTypes.has(file.content_type)
    && /^[A-Za-z0-9+/]*={0,2}$/.test(file.data || "")).map(file => [file.content_id, `data:${file.content_type};base64,${file.data}`]));
  const body = String(html || "").replace(/src="cid:([^"]+)"/g, (match, cid) => {
    let id; try { id = decodeURIComponent(cid); } catch { return match; }
    return images.has(id) ? `src="${images.get(id)}"` : match;
  });
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><style>body{padding:16px;font:15px/1.65 system-ui,sans-serif;color:#172033;overflow-wrap:anywhere}img{max-width:100%;height:auto}pre{white-space:pre-wrap}table{border-collapse:collapse}td,th{padding:6px 10px;border:1px solid #d1d5db}blockquote{border-left:3px solid #d1d5db;margin-left:0;padding-left:12px}</style></head><body>${body}</body></html>`;
}

// Only definite non-acceptance permits a new submission. A timeout, lost
// response, or already accepted message must never enable the retry action.
export function canRetryMail(result) {
  return ["rejected", "not_sent"].includes(result?.status);
}

export function mailSendFeedback(result) {
  const codes = {
    APPLE_LOGIN_REQUIRED: "请先在所属主号详情中登录 Apple 账户。",
    APPLE_SESSION_EXPIRED: "Apple 登录已过期，请在所属主号详情中重新登录。",
    APPLE_MAIL_AUTH_REJECTED: "Apple 邮件服务拒绝了发送授权，当前 Apple 登录可能仍然有效。请确认该隐私地址可用于向此收件人发信。",
    APPLE_MAIL_UNAVAILABLE: "当前 Apple 会话未提供网页邮件服务，请重新登录并确认已开通 iCloud 邮件。",
    APPLE_RATE_LIMITED: "Apple 暂时限制了发信请求。",
    ALIAS_OWNERSHIP_CONFLICT: "Apple 目录未确认这个隐私地址属于当前主号且处于启用状态。",
    ACCOUNT_DISABLED: "邮箱或所属主号已停用。",
    APPLE_MAIL_REJECTED: "Apple 拒绝了本次提交，具体原因尚未确定。可稍后重试本封邮件，系统将使用新的发送编号。",
    HME_BOOTSTRAP_UNAVAILABLE: "自动建立路由需要有效的 Apple 网页邮件会话，以及主号直连 iCloud IMAP。",
    HME_BOOTSTRAP_PREPARE_FAILED: "未能创建引导草稿，正式邮件没有发送，请检查主号 IMAP 连接。",
    HME_BOOTSTRAP_REJECTED: "引导邮件未能发送，正式邮件没有提交，请检查 Apple 邮件授权。",
    HME_BOOTSTRAP_PENDING: "尚未取得并核验引导邮件的回复路由，正式邮件没有发送；请稍后再发起发送。系统会复用已建立的引导记录。",
    MAIL_REFERENCE_PENDING: "Apple 网页邮件仍在准备回件信息，本封邮件尚未发送。请稍后重试，系统会复用已有初始化记录。",
    MAIL_REFERENCE_MISMATCH: "Apple 返回的回件信息与已核验邮件不一致，本封邮件尚未发送。请检查原始邮件是否已移动或删除。",
    MAIL_REFERENCE_CHECK_FAILED: "暂时无法核验 Apple 网页邮件的回件信息，本封邮件尚未发送。请稍后重试。",
    HME_BOOTSTRAP_RESULT_UNKNOWN: "引导邮件的状态尚未确认，正式邮件没有发送。系统不会自动重发引导邮件。",
    HME_BOOTSTRAP_INVALID: "引导邮件返回的路由未通过校验，正式邮件没有发送。",
    HME_BOOTSTRAP_STORAGE_FAILED: "引导状态未能保存，正式邮件没有发送。请先检查服务存储状态。",
    HME_SENDER_MISMATCH: "Apple 为此收件人返回了其他隐私地址。本次没有发送，也没有替换你选定的发件地址；请检查隐私邮箱与目标收件人的路由。",
    HME_RECIPIENT_MISMATCH: "Apple 返回的中继路由与收件人不一致，本次没有发送。",
    HME_FORWARDING_MISMATCH: "Apple 返回的转发邮箱与该隐私地址的所属邮箱不一致，本次没有发送。",
    HME_ROUTE_INACTIVE: "Apple 返回的隐私邮件路由已停用，本次没有发送。",
    HME_ROUTE_INVALID: "Apple 未返回完整、有效的隐私邮件中继路由，本次没有发送。",
    HME_ROUTE_REJECTED: "Apple 拒绝建立隐私邮件路由，本次没有提交邮件。请确认已开通 iCloud 邮件并将隐藏邮件转发到该邮箱。",
    HME_ROUTE_RESULT_UNKNOWN: "路由查询结果未确认，本次尚未提交邮件；Apple 可能已经创建了路由，请先核对隐私邮箱目录。",
    MAIL_ATTACHMENT_REJECTED: "Apple 拒绝了附件上传，正文尚未提交。请检查附件大小或格式后重试。",
    MAIL_ATTACHMENT_INVALID: "Apple 返回的附件信息未通过校验，正文尚未提交。",
    MAIL_ATTACHMENT_UPLOAD_UNKNOWN: "附件上传结果未确认，正文尚未提交。重试会使用新的发送编号并重新上传附件。",
  };
  if (result?.status === "accepted") return { type: "success", text: "Apple 已接受发送请求。是否送达，请以收件箱为准。" };
  if (["not_sent", "rejected"].includes(result?.status)) return { type: "error", text: codes[result.code] || "本次邮件未发送成功，请检查 Apple 登录状态和邮箱设置。" };
  return { type: "warning", text: "发送中或结果尚未确认。请查询结果，勿重复发送这封邮件。" };
}
