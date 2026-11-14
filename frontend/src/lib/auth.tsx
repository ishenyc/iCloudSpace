import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useControl, useControlSession } from './control'
type Auth = {
  session: { username: string; expiresAt?: string } | null
  checking: boolean
  sessionError: unknown
  sessionNotice: string
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  clearSession: (notice?: string) => void
}
const Context = createContext<Auth | null>(null)

export function loginNoticeMessage({ notice = '' }: { notice?: string }): string {
  switch (notice) {
    case 'session_expired': return '登录会话已过期，请重新登录。'
    case 'password_changed': return '管理员密码已更新，请使用新密码重新登录。'
    case 'credentials_rotated': return '邮箱凭据已轮换，请重新登录后确认操作记录。'
    case 'rotation_status_unknown': return '轮换结果尚未确认，请重新登录后查询原操作；不要再次提交。'
    case 'credentials_changed': return '登录凭据已经变化，请重新登录并确认操作记录。'
    case 'session_error': return '未能确认现有会话，请重新登录。'
    default: return ''
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const { sessionModel } = useControl()
  const state = useControlSession()
  const [sessionNotice, setSessionNotice] = useState('')
  const navigate = useNavigate(), location = useLocation()
  useEffect(() => {
    const notice = new URLSearchParams(window.location.search).get('notice')
    if (notice === 'password_changed' || notice === 'credentials_rotated' || notice === 'credentials_changed' || notice === 'rotation_status_unknown') {
      setSessionNotice(notice)
      sessionModel.invalidate()
    }
    else void sessionModel.refresh().catch(() => {})
    return () => sessionModel.cancelRead()
  }, [sessionModel])
  const clearSession = useCallback((notice = 'session_expired') => {
    setSessionNotice(notice)
    sessionModel.invalidate()
    window.dispatchEvent(new Event('icloudspace:session-cleared'))
    navigate('/login' + (notice ? '?notice=' + encodeURIComponent(notice) : ''), { replace: true })
  }, [navigate, sessionModel])
  const login = async (username: string, password: string) => {
    setSessionNotice('')
    await sessionModel.login({ username, password })
    const target = new URLSearchParams(location.search).get('redirect') || '/accounts'
    navigate(target.startsWith('/') && !target.startsWith('//') && !target.startsWith('/login') ? target : '/accounts', { replace: true })
  }
  const logout = async () => { setSessionNotice(''); await sessionModel.logout(); navigate('/login', { replace: true }) }
  const session = state.phase === 'authenticated' && state.operator ? { username: state.operator.username, expiresAt: state.expires_at } : null
  return <Context.Provider value={{ session, checking: state.phase === 'unresolved' && !state.error || state.phase === 'loading' || state.phase === 'changing', sessionError: state.error ?? null, sessionNotice, login, logout, clearSession }}>{children}</Context.Provider>
}
export function useAuth() { const ctx = useContext(Context); if (!ctx) throw new Error('AuthProvider is missing'); return ctx }
