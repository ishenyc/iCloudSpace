import { type ReactNode } from 'react'
import { AnimatePresence, LazyMotion, MotionConfig, m, useIsPresent, useReducedMotion, type HTMLMotionProps } from 'motion/react'

export const motionEase = [0.22, 1, 0.36, 1] as const
export const motionTiming = { fast: 0.14, content: 0.2, panel: 0.24, exit: 0.16 } as const
const loadFeatures = () => import('./motion-features').then(module => module.default)

export function MotionProvider({ children }: { children: ReactNode }) {
  return <MotionConfig reducedMotion="user" transition={{ duration: motionTiming.content, ease: motionEase }}><LazyMotion features={loadFeatures} strict>{children}</LazyMotion></MotionConfig>
}

/** Explicit UI state changes only. Polling rows must never use this wrapper. */
export function AnimatedSection({ children, style, enter = true, ...props }: HTMLMotionProps<'div'> & { enter?: boolean }) {
  const reduced = useReducedMotion()
  const present = useIsPresent()
  return <m.div data-motion="section" initial={enter ? { opacity: 0, y: reduced ? 0 : 5 } : false} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: reduced ? 0 : -3 }} transition={{ duration: reduced ? 0 : motionTiming.content, ease: motionEase }} inert={!present} aria-hidden={!present || undefined} style={{ minWidth: 0, ...style, ...(!present ? { pointerEvents: 'none' } : {}) }} {...props}>{children}</m.div>
}

export { AnimatePresence, m, useReducedMotion }
