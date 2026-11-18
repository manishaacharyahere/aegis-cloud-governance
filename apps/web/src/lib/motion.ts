/*
 * Motion tempo shared by every AEGIS component.
 *
 * Adapted from SmoothUI's lib/springs.ts and lib/animation.ts
 * (https://smoothui.dev, https://github.com/educlopez/smoothui).
 * Copyright (c) Eduardo Calvo. Licensed under the MIT License:
 * permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software, to deal in the Software without restriction, subject to
 * including this notice. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY
 * OF ANY KIND.
 */

/** Spring tiers: fast (hover, small toggles), moderate (tabs, menus), slow (dialogs). */
export const spring = {
  fast: { type: 'spring' as const, bounce: 0, duration: 0.08 },
  moderate: { type: 'spring' as const, bounce: 0, duration: 0.16 },
  slow: { type: 'spring' as const, bounce: 0.12, duration: 0.24 },
}

/** Ease-out for entering elements: cubic-bezier(.23, 1, .32, 1). */
export const EASE_OUT = [0.23, 1, 0.32, 1] as const

/** Overlays (dialogs, menus, toasts) enter with a little lift and scale. */
export const OVERLAY_INITIAL = { opacity: 0, scale: 0.97, y: 6 }
export const OVERLAY_ENTER = { opacity: 1, scale: 1, y: 0 }

/** Content entering a page: a short rise and fade. */
export const RISE_INITIAL = { opacity: 0, y: 4 }
export const RISE_ENTER = { opacity: 1, y: 0 }
