import { createContext, useContext, useState, type ReactNode } from 'react'
import { createControl } from '../control/runtime'
import type { ControlServices } from '../control/runtime'
import type { SessionSnapshot } from '../control/session'

const Services = createContext<ControlServices | null>(null)
const Session = createContext<SessionSnapshot>({ phase: 'unresolved' })

export function ControlProvider({ basePath, children }: { basePath: string; children: ReactNode }) {
  const [snapshot, setSnapshot] = useState<SessionSnapshot>({ phase: 'unresolved' })
  const [services] = useState(() => createControl({ basePath, onChange: setSnapshot }))
  return <Services.Provider value={services}><Session.Provider value={snapshot}>{children}</Session.Provider></Services.Provider>
}

export function useControl(): ControlServices {
  const value = useContext(Services)
  if (!value) throw new Error('ControlProvider is missing')
  return value
}

export function useControlSession(): SessionSnapshot { return useContext(Session) }
