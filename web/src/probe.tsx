import { useEffect, useRef, useState } from 'react'
import { ApiError, isUlid, request } from './api'
import type { Resource, Session } from './api'
import type { Copy, Language } from './copy'
import { JobTimeline } from './job-timeline'

type JobStatus = keyof Copy['probeStatus']
const terminal = new Set<JobStatus>(['SUCCEEDED', 'FAILED', 'UNKNOWN_OUTCOME', 'CANCELLED_SAFE'])
const active = new Set<JobStatus>(['QUEUED', 'INTENT_PREPARED', 'DISPATCHING', 'EXECUTING', 'VERIFYING'])
const readBudget = 30
const retryWindowMs = 23 * 60 * 60 * 1000

interface Job {
  id: string
  resource_id: string
  action: 'host.probe'
  status: JobStatus
  revision: number
  reason: string | null
}

interface Attempt {
  target: string
  key: string
  startedAt: number
  monotonicStart: number
}

type Run =
  | { phase: 'sending' | 'uncertain' | 'retry-denied' | 'rejected' | 'expired'; attempt: Attempt }
  | { phase: 'watching' | 'paused' | 'done'; attempt: Attempt; job: Job; readsLeft: number; readDenied?: boolean }

function checkedJob(value: unknown, target: string, expectedId?: string): Job {
  if (!value || typeof value !== 'object') throw new Error('Invalid observation response')
  const job = value as Job
  if (!isUlid(job.id)
      || (expectedId && job.id !== expectedId) || job.resource_id !== target || job.action !== 'host.probe'
      || (!active.has(job.status) && !terminal.has(job.status))
      || !Number.isSafeInteger(job.revision) || job.revision < 1
      || (job.reason !== null && (typeof job.reason !== 'string' || !/^[A-Z][A-Z0-9_]{1,63}$/.test(job.reason)))) {
    throw new Error('Invalid observation response')
  }
  return job
}

export function ProbeControl({ resource, session, t, lang, expired, reload }: {
  resource: Resource | null
  session: Session
  t: Copy
  lang: Language
  expired: () => void
  reload: () => void
}) {
  const [run, setRun] = useState<Run | null>(null)
  const submission = useRef<AbortController | null>(null)

  useEffect(() => () => submission.current?.abort(), [])

  async function submit(attempt: Attempt, retry = false) {
    if (submission.current) return
    // Stay inside the Controller's 24-hour request deduplication window.
    if (Math.max(Date.now() - attempt.startedAt, performance.now() - attempt.monotonicStart) >= retryWindowMs) {
      setRun({ phase: 'expired', attempt })
      return
    }
    const abort = new AbortController()
    submission.current = abort
    setRun({ phase: 'sending', attempt })
    try {
      const value = await request<unknown>('/resources/' + encodeURIComponent(attempt.target) + '/observations', {
        body: {},
        csrf: session.csrf_token,
        idempotencyKey: attempt.key,
        signal: AbortSignal.any([abort.signal, AbortSignal.timeout(15_000)]),
      })
      if (abort.signal.aborted) return
      const job = checkedJob(value, attempt.target)
      const done = terminal.has(job.status)
      setRun({ phase: done ? 'done' : 'watching', attempt, job, readsLeft: readBudget })
      if (done) reload()
    } catch (error) {
      if (abort.signal.aborted) return
      if (error instanceof ApiError && error.status === 401) expired()
      else {
        const rejected = error instanceof ApiError && error.status < 500 && ![408, 429].includes(error.status)
        // The Controller checks current access before replaying the original response.
        // Denial of a retry leaves acceptance of the earlier request unresolved.
        setRun({ phase: rejected ? (retry ? 'retry-denied' : 'rejected') : 'uncertain', attempt })
      }
    } finally {
      submission.current = null
    }
  }

  useEffect(() => {
    if (run?.phase !== 'watching') return
    const abort = new AbortController()
    const timer = window.setTimeout(async () => {
      try {
        const value = await request<unknown>('/jobs/' + encodeURIComponent(run.job.id), {
          signal: AbortSignal.any([abort.signal, AbortSignal.timeout(10_000)]),
        })
        if (abort.signal.aborted) return
        const next = checkedJob(value, run.attempt.target, run.job.id)
        const job = next.revision >= run.job.revision ? next : run.job
        const done = terminal.has(job.status)
        const readsLeft = run.readsLeft - 1
        setRun({ ...run, job, readsLeft, phase: done ? 'done' : readsLeft > 0 ? 'watching' : 'paused', readDenied: false })
        if (done) reload()
      } catch (error) {
        if (abort.signal.aborted) return
        if (error instanceof ApiError && error.status === 401) expired()
        else setRun({ ...run, phase: 'paused',
          readDenied: error instanceof ApiError && [403, 404].includes(error.status) })
      }
    }, 2000)
    return () => {
      window.clearTimeout(timer)
      abort.abort()
    }
  }, [run, expired, reload])

  const canStart = resource?.enabled && session.user.role !== 'Auditor'
  const locked = run && ['sending', 'uncertain', 'retry-denied', 'watching', 'paused'].includes(run.phase)
  if (!canStart && !run) return null

  return <div className="probe">
    <div className="probe-heading">
      <h3>{t.probeHeading}</h3>
      {canStart && <button className="primary" disabled={Boolean(locked)} onClick={() => {
        void submit({
          target: resource.id, key: crypto.randomUUID(),
          startedAt: Date.now(), monotonicStart: performance.now(),
        })
      }}>{t.probeStart}</button>}
    </div>
    {run && <div className="probe-state" role="status">
      <div className="probe-id"><span>{t.probeTarget}</span><code>{run.attempt.target}</code></div>
      {'job' in run && <>
        <div className="probe-id"><span>{t.probeJob}</span><code>{run.job.id}</code></div>
        <p><strong>{t.probeStatus[run.job.status]}</strong></p>
        {run.job.status === 'UNKNOWN_OUTCOME' && <p>{t.probeUnknown}</p>}
        {run.job.reason === 'SSH_HOST_KEY_MISMATCH' && <p>{t.probeHostKey}</p>}
        {!('readDenied' in run && run.readDenied) && <JobTimeline key={run.job.id} jobId={run.job.id} t={t} lang={lang} expired={expired}/>}
      </>}
      {run.phase === 'sending' && <p>{t.probeSending}</p>}
      {run.phase === 'rejected' && <p className="error">{t.probeDenied}</p>}
      {run.phase === 'expired' && <p className="error">{t.probeExpired}</p>}
      {(run.phase === 'uncertain' || run.phase === 'retry-denied') && <>
        <p className="error">{run.phase === 'retry-denied' ? t.probeRetryDenied : t.probeUncertain}</p>
        <button onClick={() => void submit(run.attempt, true)}>{t.probeRetry}</button>
      </>}
      {run.phase === 'paused' && <>
        <p>{run.readDenied ? t.probeUnavailable : t.probePaused}</p>
        <button onClick={() => setRun({ ...run, phase: 'watching', readsLeft: readBudget })}>{t.probeResume}</button>
      </>}
    </div>}
  </div>
}
