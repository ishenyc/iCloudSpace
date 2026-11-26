import { lazy, Suspense, useState } from 'react'
import { Link, Navigate, Route, Routes, useLocation, useSearchParams } from 'react-router-dom'
import { ArrowRight, Cloud, LockKeyhole, Mail, ShieldCheck } from 'lucide-react'
import { useAuth, loginNoticeMessage } from './lib/auth'
import { Alert, Button, Empty, Input, Loading } from './components/ui'
import { AppShell, AppearanceMenu } from './components/app-shell'

const AccountsPage = lazy(() => import('./features/accounts').then(module => ({ default: module.AccountsPage })))
const AccountDetailPage = lazy(() => import('./features/accounts').then(module => ({ default: module.AccountDetailPage })))
const AccountFormPage = lazy(() => import('./features/accounts').then(module => ({ default: module.AccountFormPage })))
const AliasesPage = lazy(() => import('./features/aliases').then(module => ({ default: module.AliasesPage })))
const ActivityPage = lazy(() => import('./features/activity').then(module => ({ default: module.ActivityPage })))
const SecurityPage = lazy(() => import('./features/security').then(module => ({ default: module.SecurityPage })))

function RequireSession() {
  const auth = useAuth(); const location = useLocation()
  if (auth.checking) return <Loading label="正在确认管理会话" />
  if (!auth.session) {
    const notice = auth.sessionNotice || (auth.sessionError ? 'session_error' : '')
    return <Navigate to={`/login?redirect=${encodeURIComponent(location.pathname + location.search)}${notice ? '&notice=' + encodeURIComponent(notice) : ''}`} replace />
  }
  return <AppShell />
}
function LoginPage() {
  const auth = useAuth(); const [search] = useSearchParams()
  const [username, setUsername] = useState('admin'); const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false); const [error, setError] = useState<any>(null)
  if (auth.checking) return <Loading label="正在确认管理会话" />
  if (auth.session) {
    const redirect = search.get('redirect') || '/accounts'
    return <Navigate to={redirect.startsWith('/') && !redirect.startsWith('//') && !redirect.startsWith('/login') ? redirect : '/accounts'} replace />
  }
  const noticeKind = search.get('notice') || auth.sessionNotice || ''
  const notice = loginNoticeMessage({ notice: noticeKind })
  return <div className="login-page">
    <aside className="login-story"><Link to="/" className="wordmark"><span className="brand-mark"><Cloud strokeWidth={1.8} /></span>iCloudSpace</Link><div><div className="eyebrow">YOUR PRIVATE MAIL SPACE</div><h2>每一个地址，<br />都有清晰的归属。</h2><p>连接主号，管理隐私邮箱。<br />让同步、凭据与每一次操作，都有迹可循。</p><div className="login-orbit"><span><Cloud /></span><span><Mail /></span><span><ShieldCheck /></span></div></div><div className="login-footnote">iCloudSpace · 自托管邮箱管理工作台</div></aside>
    <div className="login-form-area"><div className="login-appearance"><AppearanceMenu /></div><form className="login-form" onSubmit={async event => { event.preventDefault(); if (busy) return; setBusy(true); setError(null); try { await auth.login(username.trim(), password) } catch (failure) { setError(failure) } finally { setPassword(''); setBusy(false) } }}><div className="login-mobile-brand"><span className="brand-mark"><Cloud /></span>iCloudSpace</div><h1>欢迎回来</h1><p>登录你的 iCloudSpace 管理工作台。</p>{!busy && !error && !auth.sessionError && notice && <Alert tone={noticeKind === 'password_changed' || noticeKind === 'credentials_rotated' ? 'success' : 'warning'}>{notice}</Alert>}{!busy && <Alert error={error || auth.sessionError} />}<div className="stack"><label className="field"><span className="field-label">管理员账户</span><Input autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} required disabled={busy} /></label><label className="field"><span className="field-label">密码</span><Input autoComplete="current-password" type="password" placeholder="输入管理员密码" value={password} onChange={event => setPassword(event.target.value)} required disabled={busy} /></label><Button type="submit" disabled={busy || !password || !username.trim()} loading={busy} loadingLabel="正在登录…">登录工作台<ArrowRight /></Button></div><div className="login-note"><LockKeyhole />当前实例的管理员会话</div></form></div>
  </div>
}
function NotFound() { return <Empty title="页面不存在" description="这个地址可能已经变化，返回主号管理继续。" action={<Button asChild><Link to="/accounts">返回主号管理</Link></Button>} /> }
function LegacyActivity({ audit = false }: { audit?: boolean }) { const location = useLocation(); const query = new URLSearchParams(location.search); if (audit) query.set('tab', 'audit'); return <Navigate to={`/activity${query.size ? `?${query}` : ''}`} replace /> }
export default function App() {
  return <Suspense fallback={<Loading label="正在打开页面" />}><Routes><Route path="/login" element={<LoginPage />} /><Route element={<RequireSession />}><Route index element={<Navigate to="/accounts" replace />} /><Route path="accounts" element={<AccountsPage />} /><Route path="accounts/new" element={<AccountFormPage />} /><Route path="accounts/:id" element={<AccountDetailPage />} /><Route path="accounts/:id/edit" element={<AccountFormPage />} /><Route path="aliases" element={<AliasesPage />} /><Route path="aliases/archived" element={<AliasesPage view="archived" />} /><Route path="activity" element={<ActivityPage />} /><Route path="logs" element={<LegacyActivity />} /><Route path="audit" element={<LegacyActivity audit />} /><Route path="security" element={<SecurityPage />} /><Route path="*" element={<NotFound />} /></Route></Routes></Suspense>
}
