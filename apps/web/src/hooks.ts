import { useCallback, useEffect, useRef, useState, type DependencyList } from 'react'

/** Loads data when deps change; reload() fetches again (showing loading).
 * A stale response never overwrites a newer one. */
export function useLoad<T>(loader: () => Promise<T>, deps: DependencyList) {
  const [state, setState] = useState<{ data: T | null; error: unknown; loading: boolean }>({ data: null, error: null, loading: true })
  const [tick, setTick] = useState(0)
  useEffect(() => {
    let live = true
    loader().then(
      (data) => live && setState({ data, error: null, loading: false }),
      (error: unknown) => live && setState((s) => ({ ...s, error, loading: false })),
    )
    return () => {
      live = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])
  const reload = useCallback(() => {
    setState((s) => ({ ...s, loading: true }))
    setTick((t) => t + 1)
  }, [])
  return { ...state, reload }
}

/** Runs an action with busy/error state. */
export function useAction() {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const run = useCallback(async <T,>(f: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true)
    setError(null)
    try {
      return await f()
    } catch (e) {
      setError(e)
      return undefined
    } finally {
      setBusy(false)
    }
  }, [])
  return { busy, error, run, setError }
}

/** State that survives reloads and re-sign-in (sessionStorage, this tab only).
 * Key it by what it describes (e.g. rule + resource) so drafts never leak
 * between forms. clear() removes the draft after a successful submit. */
export function useDraft(key: string, initial: string): [string, (v: string) => void, () => void] {
  const k = `aegis.draft.${key}`
  const read = useCallback(() => {
    try {
      return sessionStorage.getItem(k) ?? initial
    } catch {
      return initial
    }
  }, [k, initial])
  const [state, setState] = useState<{ key: string; value: string }>(() => ({ key: k, value: read() }))
  // A different key (e.g. another resource) starts from its own draft.
  const value = state.key === k ? state.value : read()
  const set = useCallback((v: string) => {
    setState({ key: k, value: v })
    try {
      sessionStorage.setItem(k, v)
    } catch {
      /* storage unavailable: keep in memory */
    }
  }, [k])
  const clear = useCallback(() => {
    try {
      sessionStorage.removeItem(k)
    } catch {
      /* ignore */
    }
  }, [k])
  return [value, set, clear]
}

/** Accumulating "load more" list over a keyset-paged endpoint. The loader
 * gets the cursor ('' for the first page); changing deps or reload() starts
 * over, and responses from an older generation are ignored. */
export function usePaged<T>(loader: (after: string) => Promise<{ items: T[]; next_cursor?: string }>, deps: DependencyList) {
  const [state, setState] = useState<{ items: T[]; next: string; error: unknown; loading: boolean }>({ items: [], next: '', error: null, loading: true })
  const [tick, setTick] = useState(0)
  const gen = useRef(0)
  useEffect(() => {
    const g = ++gen.current
    loader('').then(
      (p) => g === gen.current && setState({ items: p.items, next: p.next_cursor ?? '', error: null, loading: false }),
      (error: unknown) => g === gen.current && setState((s) => ({ ...s, error, loading: false })),
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])
  const more = useCallback(() => {
    const g = gen.current
    setState((s) => ({ ...s, loading: true }))
    loader(state.next).then(
      (p) => g === gen.current && setState((s) => ({ items: [...s.items, ...p.items], next: p.next_cursor ?? '', error: null, loading: false })),
      (error: unknown) => g === gen.current && setState((s) => ({ ...s, error, loading: false })),
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.next])
  const reload = useCallback(() => {
    setState((s) => ({ ...s, loading: true }))
    setTick((t) => t + 1)
  }, [])
  return { ...state, more, reload }
}

/** Polls fetch() until done(value) is true. Each poll is scheduled only after
 * the previous one returned (no overlap, no out-of-order results), the delay
 * backs off, and polling stops after maxPolls. */
export function usePoll<T>(initial: T | null, fetch: (v: T) => Promise<T>, done: (v: T) => boolean, opts: { every?: number; max?: number; maxPolls?: number } = {}) {
  const [value, setValue] = useState<T | null>(initial)
  const [gaveUp, setGaveUp] = useState(false)
  const every = opts.every ?? 2000
  const maxDelay = opts.max ?? 10_000
  const maxPolls = opts.maxPolls ?? 120
  const fetchRef = useRef(fetch)
  const doneRef = useRef(done)
  useEffect(() => {
    fetchRef.current = fetch
    doneRef.current = done
  })
  const running = value !== null && !done(value)
  const id = (value as { id?: string } | null)?.id
  useEffect(() => {
    if (value === null || doneRef.current(value)) return
    let live = true
    let polls = 0
    let timer: number | undefined
    let current: T = value
    const tick = async (delay: number) => {
      timer = window.setTimeout(async () => {
        if (!live) return
        polls++
        try {
          current = await fetchRef.current(current)
          if (!live) return
          setValue(current)
          if (doneRef.current(current)) return
        } catch {
          /* transient: keep polling with backoff */
        }
        if (polls >= maxPolls) {
          setGaveUp(true)
          return
        }
        void tick(Math.min(maxDelay, delay * 1.5))
      }, delay)
    }
    void tick(every)
    return () => {
      live = false
      window.clearTimeout(timer)
    }
    // Restart only when a new item starts being watched.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running, id])
  const start = useCallback((v: T) => {
    setGaveUp(false)
    setValue(v)
  }, [])
  return { value, start, gaveUp, running }
}

export const usd = (n: number) => n.toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 2 })
export const usdCompact = (n: number) => n.toLocaleString('en-US', { style: 'currency', currency: 'USD', notation: n >= 100_000 ? 'compact' : 'standard', maximumFractionDigits: n >= 100_000 ? 1 : 0 })
export const when = (s?: string) => (s ? new Date(s).toLocaleString() : '—')
export const pct = (n: number) => `${(n * 100).toFixed(1)} %`

/** "3 hours ago" style relative time. */
export function ago(s?: string, now = Date.now()): string {
  if (!s) return '—'
  const sec = Math.round((now - new Date(s).getTime()) / 1000)
  if (!Number.isFinite(sec)) return '—'
  const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })
  const steps: [number, Intl.RelativeTimeFormatUnit][] = [[60, 'second'], [60, 'minute'], [24, 'hour'], [30, 'day'], [12, 'month'], [Infinity, 'year']]
  let v = -sec
  for (const [n, unit] of steps) {
    if (Math.abs(v) < n) return rtf.format(Math.round(v), unit)
    v /= n
  }
  return when(s)
}
