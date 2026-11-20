import { useEffect, useState } from 'react'
import { hasApiStatus, isUlid, request } from './api'
import type { Session } from './api'
import type { Copy, Language } from './copy'

export type RestartRoute = { planId: string; revision: number; operationId: string }

export function restartHash({ planId, revision, operationId }: RestartRoute) {
  return `#restart/${planId}/${revision}/${operationId}`
}

export function readRestartHash(hash: string): RestartRoute | null {
  const [prefix, planId, rawRevision, operationId, extra] = hash.split('/')
  const revision = Number(rawRevision)
  return prefix === '#restart' && extra === undefined && isUlid(planId) && isUlid(operationId) &&
    /^[1-9][0-9]{0,9}$/.test(rawRevision) && revision <= 2_147_483_647
    ? { planId, revision, operationId } : null
}

type Entry = { seq: number; at: number; revision: number; operation_id: string; status: string; reason: string | null; attempt?: number }
const pending = new Set(['QUEUED', 'INTENT_PREPARED', 'DISPATCHING', 'RECONCILIATION_REQUESTED'])

export function RestartTimeline({ route, t, lang, expired, session }: {
  session: Session; route: RestartRoute; t: Copy; lang: Language; expired: () => void
}) {
  const { planId, operationId, revision } = route
  const [entries, setEntries] = useState<Entry[] | null>(null)
  const [error, setError] = useState<'denied' | 'failed' | null>(null)
  const [refresh, setRefresh] = useState(0)

  useEffect(() => {
    const abort = new AbortController()
    let timer: number | undefined
    setError(null)
    async function load() {
      try {
        const { items } = await request<{ items: Entry[] }>(`/change-plans/${planId}/execution-timeline`, { signal: abort.signal })
        if (abort.signal.aborted) return
        const rows = items.filter(item => item.operation_id === operationId && item.revision === revision)
        setEntries(rows)
        if (pending.has(rows.at(-1)?.status ?? '')) timer = window.setTimeout(load, 2000)
      } catch (cause) {
        if (abort.signal.aborted) return
        if (hasApiStatus(cause, 401)) return expired()
        if (hasApiStatus(cause, 403, 404)) {
          setEntries(null)
          setError('denied')
        } else {
          setError('failed')
        }
      }
    }
    void load()
    return () => { abort.abort(); window.clearTimeout(timer) }
  }, [planId, operationId, revision, expired, refresh])

  const history = entries ?? []
  const last = history.at(-1)
  const attempt = (last?.attempt ?? 0) + 1
  const [sending, setSending] = useState(false)
  async function reconcile() {
    setSending(true)
    try {
      await request(`/change-plans/${planId}/execution-requests/${operationId}/reconciliations/${attempt}`, { body: {}, csrf: session.csrf_token })
      setRefresh(value => value + 1)
    } catch (cause) {
      if (hasApiStatus(cause, 401)) expired()
      else setError(hasApiStatus(cause, 403, 404) ? 'denied' : 'failed')
    } finally {
      setSending(false)
    }
  }
  const format = new Intl.DateTimeFormat(lang, { dateStyle: 'medium', timeStyle: 'medium' })
  const label = (status: string) => Object.hasOwn(t.restartStates, status)
    ? t.restartStates[status as keyof Copy['restartStates']] : status
  const needsCheck = last?.status === 'UNKNOWN_OUTCOME' || last?.status === 'QUARANTINED'
  return <div className="workspace">
    <section aria-label={t.restartTimeline} className="panel">
      <div className="panel-heading"><h1>{t.restartTimeline}</h1>
        {error === 'failed' && <button type="button" onClick={() => setRefresh(value => value + 1)}>{t.retry}</button>}
      </div>
      {error && <p className="notice error" role="alert">{error === 'denied' ? t.restartTimelineDenied : t.requestError}</p>}
      {entries === null && !error && <p className="notice" role="status">{t.loading}</p>}
      {entries?.length === 0 && <p className="notice" role="status">{t.timelineEmpty}</p>}
      {last && <>
        <div className="restart-result" role="status">
          <h2>{label(last.status)}</h2>
          {needsCheck && <p>{t.restartUnknownHelp}</p>}
          {last.status === 'RECONCILIATION_REQUESTED' && <p>{t.restartReconcileHelp}</p>}
          {last.status === 'SUCCEEDED' && <p>{t.restartVerifiedHelp}</p>}
        </div>
        {session.user.role === 'Owner' && attempt <= 3 && needsCheck &&
          <button type="button" disabled={sending} onClick={reconcile}>{t.restartReconcile}</button>}
        <details className="restart-events">
          <summary>{t.restartEvents}</summary>
          <p>{t.restartRevision} {revision} · <code>{operationId}</code></p>
          <ol className="audit-list" reversed>{history.slice().reverse().map(item => <li key={item.seq}>
            <strong>{label(item.status)}</strong>
            {Number.isSafeInteger(item.at) && item.at >= 0 && item.at <= 253402300799 && <> · {format.format(item.at * 1000)}</>}
            {item.reason && <> · <code>{item.reason}</code></>}
          </li>)}</ol>
        </details>
      </>}
    </section>
  </div>
}
