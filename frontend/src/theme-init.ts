let theme = 'dark'
try { theme = localStorage.getItem('icloudspace-theme') || 'dark' } catch {}
const resolved = theme === 'system' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme
document.documentElement.dataset.theme = resolved
document.documentElement.classList.toggle('dark', resolved === 'dark')
document.documentElement.style.colorScheme = resolved
export {}
