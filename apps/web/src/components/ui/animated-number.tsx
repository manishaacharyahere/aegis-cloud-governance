import { useState } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'

/*
 * A number that rolls up or down when it changes. Adapted from SmoothUI's
 * CountBadge AnimatedCount (MIT, https://smoothui.dev): the new value slides
 * in from the direction of change. Respects prefers-reduced-motion.
 */
export function AnimatedNumber({ value, format = (n) => n.toLocaleString() }: {
  value: number
  format?: (n: number) => string
}) {
  const reduce = useReducedMotion()
  // Direction of the last change, derived while rendering (no effect needed).
  const [prev, setPrev] = useState(value)
  const [direction, setDirection] = useState(1)
  if (value !== prev) {
    setDirection(value > prev ? 1 : -1)
    setPrev(value)
  }

  if (reduce) return <span className="tabular-nums">{format(value)}</span>
  return (
    <span className="relative inline-flex overflow-hidden tabular-nums">
      <AnimatePresence initial={false} mode="popLayout">
        <motion.span
          key={value}
          className="inline-block"
          initial={{ opacity: 0, y: direction * 14, filter: 'blur(2px)' }}
          animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
          exit={{ opacity: 0, y: direction * -14, filter: 'blur(2px)' }}
          transition={{ type: 'spring', bounce: 0.1, duration: 0.35 }}
        >
          {format(value)}
        </motion.span>
      </AnimatePresence>
    </span>
  )
}
