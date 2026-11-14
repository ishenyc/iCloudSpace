import { StrictMode, Component, type ReactNode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { AuthProvider } from './lib/auth'
import { ControlProvider } from './lib/control'
import { readInstallationBootstrap } from './control/bootstrap'
import { configureEntryHandoff } from './control/entry-handoff'
import { ToastProvider, TooltipProvider } from './components/ui'
import { RefreshButton } from './components/refresh-button'
import { MotionProvider } from './lib/motion'
import App from './App'
import './theme-init'
import './styles.css'

class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  render() { return this.state.failed ? <div className="empty"><h1>页面暂时无法显示</h1><p>刷新页面重新读取服务状态。</p><RefreshButton variant="outline" onRefresh={() => location.reload()}>刷新页面</RefreshButton></div> : this.props.children }
}
function InstalledApp() {
  const bootstrap = readInstallationBootstrap(document)
  configureEntryHandoff(bootstrap.control_path, bootstrap.previous_control_path)
  return <ControlProvider basePath={bootstrap.control_path}><BrowserRouter basename={bootstrap.ui_path}><AuthProvider><TooltipProvider><ToastProvider><App /></ToastProvider></TooltipProvider></AuthProvider></BrowserRouter></ControlProvider>
}
createRoot(document.getElementById('root')!).render(<StrictMode><ErrorBoundary><MotionProvider><InstalledApp /></MotionProvider></ErrorBoundary></StrictMode>)
