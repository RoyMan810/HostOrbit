import { useEffect, useState } from 'react'
import { ApiError, request } from './api'
import type { Copy, Language } from './copy'
import { isJobId, JobTimeline } from './job-timeline'

type AuditEvent = {
  seq: number
  event: { at: number; actor_id: string; event: string; target_id: string; outcome: string; correlation_id: string }
}

const jobEvents = new Set(['job.accepted', 'job.transition', 'job.finished'])

export function Audit({ t, lang, expired }: { t: Copy; lang: Language; expired: () => void }) {
  const [cursors, setCursors] = useState([0])
  const [revision, refresh] = useState(0)
  const [items, setItems] = useState<AuditEvent[] | null>(null)
  const [error, setError] = useState<unknown>(null)
  const after = cursors[cursors.length - 1]

  useEffect(() => {
    const abort = new AbortController()
    setItems(null)
    setError(null)
    request<{ items: AuditEvent[] }>(`/audit?after=${after}`, { signal: abort.signal })
      .then(result => { if (!abort.signal.aborted) setItems(result.items) })
      .catch(err => {
        if (abort.signal.aborted) return
        if (err instanceof ApiError && err.status === 401) expired()
        else setError(err)
      })
    return () => abort.abort()
  }, [after, revision, expired])

  return <main id="main" className="workspace">
    <div className="heading">
      <div><p className="eyebrow">{t.workspace}</p><h1>{t.audit}</h1><p>{t.auditHint}</p></div>
      <button onClick={() => refresh(value => value + 1)} disabled={items == null && error == null}>{t.auditRefresh}</button>
    </div>
    <section className="panel" aria-label={t.audit}>
      {error != null ? <p className="notice error" role="alert">
        {error instanceof ApiError && error.status === 403 ? t.auditDenied : t.requestError}
      </p> : items == null ? <p className="notice" role="status">{t.loading}</p> : items.length === 0 ?
        <p className="notice">{t.auditEmpty}</p> : <ol className="audit-list">
          {items.map(({ seq, event }) => <li key={seq}>
            <strong>{event.event}</strong> <span id={`audit-event-${seq}`}>#{seq} · {event.outcome}</span>
            <dl className="audit-facts">
              <div><dt>{t.auditTime}</dt><dd>{new Intl.DateTimeFormat(lang, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(event.at * 1000))}</dd></div>
              <div><dt>{t.auditActor}</dt><dd><code>{event.actor_id}</code></dd></div>
              <div><dt>{t.auditTarget}</dt><dd><code>{event.target_id}</code></dd></div>
              <div><dt>{t.auditCorrelation}</dt><dd><code>{event.correlation_id}</code></dd></div>
            </dl>
            {jobEvents.has(event.event) && isJobId(event.correlation_id) &&
              <JobTimeline jobId={event.correlation_id} t={t} lang={lang} expired={expired}
                describedBy={`audit-event-${seq}`}/>}
          </li>)}
        </ol>}
      {(cursors.length > 1 || (items?.length === 100)) && <div className="pager">
        <button disabled={cursors.length < 2 || items == null} onClick={() => setCursors(values => values.slice(0, -1))}>{t.previous}</button>
        <button disabled={items?.length !== 100} onClick={() => {
          if (items?.length === 100) setCursors(values => [...values, items[items.length - 1].seq])
        }}>{t.next}</button>
      </div>}
    </section>
  </main>
}
