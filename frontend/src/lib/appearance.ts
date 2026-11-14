import { useEffect, useState } from 'react'

export type Appearance = 'dark' | 'light' | 'system'
const read = (): Appearance => {
  try { const value = localStorage.getItem('icloudspace-theme'); if (value === 'light' || value === 'system') return value } catch {}
  return 'dark'
}
export function useAppearance() {
  const [theme, setTheme] = useState<Appearance>(read)
  useEffect(() => {
    const media = matchMedia('(prefers-color-scheme: dark)')
    const apply = () => {
      const resolved = theme === 'system' ? (media.matches ? 'dark' : 'light') : theme
      document.documentElement.dataset.theme = resolved
      document.documentElement.classList.toggle('dark', resolved === 'dark')
      document.documentElement.style.colorScheme = resolved
      document.querySelector('meta[name=theme-color]')?.setAttribute('content', resolved === 'dark' ? '#1d1d1d' : '#eeefef')
    }
    apply(); media.addEventListener('change', apply)
    try { localStorage.setItem('icloudspace-theme', theme) } catch {}
    return () => media.removeEventListener('change', apply)
  }, [theme])
  useEffect(() => {
    const sync = (event: StorageEvent) => { if (event.key === null || event.key === 'icloudspace-theme') setTheme(read()) }
    const syncLocal = (event: Event) => setTheme((event as CustomEvent<Appearance>).detail)
    window.addEventListener('storage', sync); window.addEventListener('icloudspace:appearance', syncLocal)
    return () => { window.removeEventListener('storage', sync); window.removeEventListener('icloudspace:appearance', syncLocal) }
  }, [])
  const update = (value: Appearance) => {
    setTheme(value)
    try { localStorage.setItem('icloudspace-theme', value) } catch {}
    window.dispatchEvent(new CustomEvent('icloudspace:appearance', { detail: value }))
  }
  return [theme, update] as const
}
