interface ClipboardEnvironment {
  window: Pick<Window, 'isSecureContext'>
  navigator: Pick<Navigator, 'clipboard'>
  document: Document
}

/** Clipboard permissions can reject even in a secure browser. The temporary
 * selection is removed on every outcome and never retained as page state. */
export async function copyText(value: string, environment: ClipboardEnvironment = { window, navigator, document }): Promise<void> {
  if (!value) throw new Error('没有可复制的内容')
  try {
    if (environment.window.isSecureContext && environment.navigator.clipboard) {
      await environment.navigator.clipboard.writeText(value)
      return
    }
  } catch { /* A browser permission failure can still permit selection copy. */ }
  const document = environment.document, active = document.activeElement
  const selection = active instanceof Object && 'selectionStart' in active && 'selectionEnd' in active ? [active.selectionStart, active.selectionEnd] : null
  const input = document.createElement('textarea')
  input.className = 'clipboard-proxy'; input.value = value
  input.setAttribute('readonly', ''); input.setAttribute('aria-hidden', 'true'); input.tabIndex = -1
  document.body.appendChild(input)
  try {
    input.select()
    if (!document.execCommand('copy')) throw new Error('copy unavailable')
  } catch { throw new Error('复制失败，请手动选择并复制') }
  finally {
    input.value = ''; input.remove()
    if (active && 'focus' in active && typeof active.focus === 'function') active.focus({ preventScroll: true })
    if (selection && active && 'setSelectionRange' in active && typeof active.setSelectionRange === 'function' && typeof selection[0] === 'number' && typeof selection[1] === 'number') active.setSelectionRange(selection[0], selection[1])
  }
}
