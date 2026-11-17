import { useCallback, useEffect, useState, type DependencyList } from 'react'

/** Loads data when deps change; reload() fetches again. State changes happen
 * only in promise callbacks, and a stale response never overwrites a newer one. */
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
  const reload = useCallback(() => setTick((t) => t + 1), [])
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
 * clear() removes the draft after a successful submit. */
export function useDraft(key: string, initial: string): [string, (v: string) => void, () => void] {
  const k = `aegis.draft.${key}`
  const [value, setValue] = useState<string>(() => {
    try {
      return sessionStorage.getItem(k) ?? initial
    } catch {
      return initial
    }
  })
  const set = useCallback((v: string) => {
    setValue(v)
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

export const usd = (n: number) => n.toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 2 })
export const when = (s?: string) => (s ? new Date(s).toLocaleString() : '—')
export const pct = (n: number) => `${(n * 100).toFixed(1)} %`

/** Accumulating "load more" list over a keyset-paged endpoint. The loader
 * gets the cursor ('' for the first page); changing deps starts over. */
export function usePaged<T>(loader: (after: string) => Promise<{ items: T[]; next_cursor?: string }>, deps: DependencyList) {
  const [state, setState] = useState<{ items: T[]; next: string; error: unknown; loading: boolean }>({ items: [], next: '', error: null, loading: true })
  const [tick, setTick] = useState(0)
  useEffect(() => {
    let live = true
    loader('').then(
      (p) => live && setState({ items: p.items, next: p.next_cursor ?? '', error: null, loading: false }),
      (error: unknown) => live && setState((s) => ({ ...s, error, loading: false })),
    )
    return () => {
      live = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])
  const more = useCallback(() => {
    setState((s) => ({ ...s, loading: true }))
    loader(state.next).then(
      (p) => setState((s) => ({ items: [...s.items, ...p.items], next: p.next_cursor ?? '', error: null, loading: false })),
      (error: unknown) => setState((s) => ({ ...s, error, loading: false })),
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.next])
  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { ...state, more, reload }
}
