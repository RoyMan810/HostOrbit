import { useEffect, useState } from 'react'
import { ApiError, isUlid, request } from './api'
import type { Copy, Language } from './copy'
import { JobTimeline } from './job-timeline'

type AuditEvent = {
  seq: number
  event: {
    at: number; actor_id: string; event: string; target_id: string; outcome: string; correlation_id: string
    details?: { revision?: unknown }
  }
}

type AuditEntry = AuditEvent & { planRevision: number | null }

const jobEvents = new Set(['job.accepted', 'job.transition', 'job.finished'])
const authOutcomes = new Map([
  ['auth.login', 'SUCCEEDED'],
  ['auth.login_failed', 'DENIED'],
  ['auth.login_limited', 'DENIED'],
  ['auth.logout', 'SUCCEEDED'],
  ['auth.reauthenticated', 'SUCCEEDED'],
  ['auth.reauth_failed', 'DENIED'],
  ['auth.reauth_limited', 'DENIED'],
])
const accessOutcomes = new Map([
  ['owner.bootstrap_issued', 'SUCCEEDED'],
  ['owner.created', 'SUCCEEDED'],
  ['user.created', 'SUCCEEDED'],
  ['user.permissions_changed', 'SUCCEEDED'],
])

function auditExportTime(at: number) {
  return Number.isSafeInteger(at) && at >= 0 && at <= 253402300799 ? new Date(at * 1000).toISOString() : null
}

function sshAuditExport(items: AuditEvent[], statuses: Copy['probeStatus']) {
  const jobs = new Map<string, number>()
  const events = []
  for (const { event } of items) {
    const { at, event: kind, outcome, correlation_id: jobId } = event
    if (!jobEvents.has(kind) || !isUlid(jobId) || !Object.hasOwn(statuses, outcome)) continue
    const timestamp = auditExportTime(at)
    if (timestamp === null) continue
    const job = jobs.get(jobId) ?? jobs.size + 1
    jobs.set(jobId, job)
    events.push({ job, event: kind, outcome, at: timestamp })
  }
  return events.length ? JSON.stringify({ version: 1, events }, null, 2) : null
}

function auditOutcomeExport(items: AuditEvent[], outcomes: ReadonlyMap<string, string>) {
  const events = []
  for (const { event: { at, event, outcome } } of items) {
    const expected = outcomes.get(event)
    if (expected === undefined || outcome !== expected) continue
    const timestamp = auditExportTime(at)
    if (timestamp !== null) events.push({ event, outcome, at: timestamp })
  }
  return events.length ? JSON.stringify({ version: 1, events }, null, 2) : null
}

function savedPlanRevision(event: AuditEvent['event']) {
  const revision = event.details?.revision
  if (event.event !== 'change_plan.draft_saved' || event.outcome !== 'SUCCEEDED'
      || !isUlid(event.correlation_id) || !isUlid(event.target_id)
      || typeof revision !== 'number' || !Number.isSafeInteger(revision) || revision < 1) return null
  return revision
}

function planAuditExport(entries: AuditEntry[]) {
  const plans = new Map<string, number>()
  const events = []
  for (const { event, planRevision } of entries) {
    if (planRevision === null) continue
    const timestamp = auditExportTime(event.at)
    if (timestamp === null) continue
    const key = `${event.target_id}:${event.correlation_id}`
    const plan = plans.get(key) ?? plans.size + 1
    plans.set(key, plan)
    events.push({ plan, revision: planRevision, event: event.event, outcome: event.outcome, at: timestamp })
  }
  return events.length ? JSON.stringify({ version: 1, events }, null, 2) : null
}

function AuditExport({ json, summary, scope, filename, download }: {
  json: string; summary: string; scope: string; filename: string; download: string
}) {
  return <details className="audit-export" name="audit-export">
    <summary>{summary}</summary>
    <p>{scope}</p>
    <pre tabIndex={0}>{json}</pre>
    <a download={filename} href={`data:application/json;charset=utf-8,${encodeURIComponent(json)}`}>{download}</a>
  </details>
}

function IntegrityCheck({ t, expired }: { t: Copy; expired: () => void }) {
  const [status, setStatus] = useState<'idle' | 'checking' | 'verified' | 'invalid' | 'denied' | 'unavailable'>('idle')
  useEffect(() => {
    if (status !== 'checking') return
    const abort = new AbortController()
    request<{ status: 'verified' | 'invalid' }>('/audit/integrity', { signal: abort.signal })
      .then(result => {
        if (!abort.signal.aborted) setStatus(result.status === 'verified' || result.status === 'invalid'
          ? result.status : 'unavailable')
      })
      .catch(err => {
        if (abort.signal.aborted) return
        if (err instanceof ApiError && err.status === 401) expired()
        else setStatus(err instanceof ApiError && err.status === 403 ? 'denied' : 'unavailable')
      })
    return () => abort.abort()
  }, [status, expired])

  return <div className="panel-heading">
    <button onClick={() => setStatus('checking')} disabled={status === 'checking'}>{t.auditVerify}</button>
    {status === 'checking' && <p role="status">{t.auditChecking}</p>}
    {status === 'verified' && <p role="status">{t.auditVerified}</p>}
    {status === 'invalid' && <p className="error" role="alert">{t.auditInvalid}</p>}
    {status === 'denied' && <p className="error" role="alert">{t.auditDenied}</p>}
    {status === 'unavailable' && <p className="error" role="alert">{t.auditVerifyUnavailable}</p>}
  </div>
}

export function Audit({ t, lang, expired }: { t: Copy; lang: Language; expired: () => void }) {
  const [cursors, setCursors] = useState([0])
  const [revision, refresh] = useState(0)
  const [items, setItems] = useState<AuditEvent[] | null>(null)
  const [error, setError] = useState<unknown>(null)
  const after = cursors[cursors.length - 1]
  const sshExport = items && sshAuditExport(items, t.probeStatus)
  const authExport = items && auditOutcomeExport(items, authOutcomes)
  const accessExport = items && auditOutcomeExport(items, accessOutcomes)
  const entries = items?.map(item => ({ ...item, planRevision: savedPlanRevision(item.event) })) ?? []
  const planExport = planAuditExport(entries)

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
      {items != null && <IntegrityCheck t={t} expired={expired}/>}
      {sshExport && <AuditExport key={`ssh:${after}:${revision}`} json={sshExport}
        summary={t.auditExportReview} scope={t.auditExportScope} filename="hostorbit-ssh-audit.json" download={t.auditExportDownload}/>}
      {authExport && <AuditExport key={`auth:${after}:${revision}`} json={authExport}
        summary={t.auditAuthExportReview} scope={t.auditAuthExportScope} filename="hostorbit-auth-audit.json" download={t.auditExportDownload}/>}
      {accessExport && <AuditExport key={`access:${after}:${revision}`} json={accessExport}
        summary={t.auditAccessExportReview} scope={t.auditAccessExportScope} filename="hostorbit-access-audit.json" download={t.auditExportDownload}/>}
      {planExport && <AuditExport key={`plan:${after}:${revision}`} json={planExport}
        summary={t.auditPlanExportReview} scope={t.auditPlanExportScope} filename="hostorbit-change-plan-audit.json" download={t.auditExportDownload}/>}
      {error != null ? <p className="notice error" role="alert">
        {error instanceof ApiError && error.status === 403 ? t.auditDenied : t.requestError}
      </p> : items == null ? <p className="notice" role="status">{t.loading}</p> : items.length === 0 ?
        <p className="notice">{t.auditEmpty}</p> : <ol className="audit-list">
          {entries.map(({ seq, event, planRevision }) => {
            const related = planRevision === null ? [] : entries.filter(entry =>
              entry.planRevision !== null && entry.planRevision !== planRevision
              && entry.event.correlation_id === event.correlation_id && entry.event.target_id === event.target_id)
            const previous = related.filter(entry => entry.seq < seq).at(-1)
            const next = related.find(entry => entry.seq > seq)
            return <li key={seq}>
              <strong>{event.event}</strong> <span id={`audit-event-${seq}`} tabIndex={planRevision === null ? undefined : -1}>#{seq} · {event.outcome}</span>
              <dl className="audit-facts">
                <div><dt>{t.auditTime}</dt><dd>{new Intl.DateTimeFormat(lang, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(event.at * 1000))}</dd></div>
                <div><dt>{t.auditActor}</dt><dd><code>{event.actor_id}</code></dd></div>
                <div><dt>{t.auditTarget}</dt><dd><code>{event.target_id}</code></dd></div>
                <div><dt>{planRevision === null ? t.auditCorrelation : t.auditPlan}</dt><dd><code>{event.correlation_id}</code></dd></div>
                {planRevision !== null && <div><dt>{t.auditPlanRevision}</dt><dd>{planRevision}</dd></div>}
              </dl>
              {(previous || next) && <div className="audit-plan-links">
                <p>{t.auditPlanRelated}</p>
                <ul>{[previous, next].filter(entry => entry !== undefined).map(entry => <li key={entry.seq}>
                  <a href={`#audit-event-${entry.seq}`}>{t.auditPlanRevision} {entry.planRevision} · #{entry.seq}</a>
                </li>)}</ul>
              </div>}
              {jobEvents.has(event.event) && isUlid(event.correlation_id) &&
                <JobTimeline jobId={event.correlation_id} t={t} lang={lang} expired={expired}
                  describedBy={`audit-event-${seq}`}/>}
            </li>
          })}
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
