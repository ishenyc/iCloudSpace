import { MorphIcon, type IconNode, type MorphIconProps } from 'morphicons/react'
import { Check, Copy, Folder, FolderOpen, Menu, Monitor, Moon, PanelLeftClose, PanelLeftOpen, RefreshCw, Search, Sun, X } from 'lucide'
import { cn } from '../lib/utils'

// Morphicons consumes IconNode data rather than lucide-react components.
// Keep these named imports aligned with the static Lucide icon version so the
// resting shapes and stroke proportions stay consistent throughout the app.
// Lucide 0.468 wraps its child nodes in an outer SVG tuple; Morphicons expects
// just those child nodes. Adapt once at module scope rather than at render.
const node = (icon: typeof Check): IconNode => icon[2] ?? []
const icons = {
  check: node(Check),
  close: node(X),
  copy: node(Copy),
  folder: node(Folder),
  'folder-open': node(FolderOpen),
  menu: node(Menu),
  moon: node(Moon),
  'panel-close': node(PanelLeftClose),
  'panel-open': node(PanelLeftOpen),
  refresh: node(RefreshCw),
  search: node(Search),
  sun: node(Sun),
  system: node(Monitor),
} as const

export type AnimatedIconName = keyof typeof icons
export type AnimatedIconProps = Omit<MorphIconProps, 'icon' | 'from' | 'to' | 'progress' | 'spring' | 'reducedMotion'> & {
  name: AnimatedIconName
}

/** Small state transitions only; reduced motion immediately shows the target. */
export function AnimatedIcon({ name, size = 16, strokeWidth = 1.6, className, style, ...props }: AnimatedIconProps) {
  return <MorphIcon
    {...props}
    data-slot="animated-icon"
    icon={icons[name]}
    size={size}
    strokeWidth={strokeWidth}
    spring="smooth"
    reducedMotion="user"
    className={cn('shrink-0', className)}
    style={{ width: size, height: size, ...style }}
  />
}

type StateIconProps = Omit<AnimatedIconProps, 'name'>

export function SidebarToggleIcon({ collapsed, ...props }: StateIconProps & { collapsed: boolean }) {
  return <AnimatedIcon {...props} name={collapsed ? 'panel-open' : 'panel-close'} />
}

export function MenuToggleIcon({ open, ...props }: StateIconProps & { open: boolean }) {
  return <AnimatedIcon {...props} name={open ? 'close' : 'menu'} />
}

export function ThemeIcon({ theme, ...props }: StateIconProps & { theme: string }) {
  return <AnimatedIcon {...props} name={theme === 'light' ? 'sun' : theme === 'system' ? 'system' : 'moon'} />
}

export function CopyStatusIcon({ copied, ...props }: StateIconProps & { copied: boolean }) {
  return <AnimatedIcon {...props} name={copied ? 'check' : 'copy'} />
}

export function FolderStateIcon({ open, ...props }: StateIconProps & { open: boolean }) {
  return <AnimatedIcon {...props} name={open ? 'folder-open' : 'folder'} />
}

export function RefreshIcon({ refreshing, className, ...props }: StateIconProps & { refreshing: boolean }) {
  return <AnimatedIcon {...props} name="refresh" className={cn(refreshing && 'animate-spin motion-reduce:animate-none', className)} />
}
