import { useEffect, useRef, useState } from 'react'
import { ApiError, hasApiStatus, isUlid, request } from './api'
import type { DockerContainer, Observation, Resource } from './api'
import type { Copy } from './copy'
import { restartHash } from './restart-timeline'

type Draft = {
  id: string
  revision: number
  plan_hash: string
  action: string
  diff: { operation: string; configuration: string }
  baseline: {
    target: DockerContainer & { resource_id: string }
    boot_id: string
    started_at?: string
    observed_at: number
    resource_revision: number
    policy_revision: number
  }
}
type SavedDraft = { id: string; revision: number; hash: string; tag: string; key: string; savedAt: number }

export function RestartPlan({ resource, container, sample, csrf, t, expired }: {
  resource: Resource
  container: DockerContainer
  sample: NonNullable<Observation['last_success']>
  csrf: string
  t: Copy
  expired: () => void
}) {
  const [confirmed, confirm] = useState(false)
  const [draft, setDraft] = useState<SavedDraft | null>(null)
  const [probe, setProbe] = useState<string | null>(null)
  const [decision, setDecision] = useState<'waiting' | 'passed' | 'denied' | 'failed'>('waiting')
  const [password, setPassword] = useState('')
  const [approval, setApproval] = useState<string | null>(null)
  const [operation, setOperation] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef<AbortController | null>(null)
  useEffect(() => () => pending.current?.abort(), [])

  const plan = draft && '/change-plans/' + draft.id
  const options = { csrf, ifMatch: draft?.tag, idempotencyKey: draft?.key }
  const evidence = draft && probe ? { probe_id: probe, request_key: draft.key } : null

  async function run(action: (signal: AbortSignal) => Promise<void>) {
    if (pending.current) return
    const abort = new AbortController()
    pending.current = abort
    setBusy(true)
    setError('')
    try {
      await action(abort.signal)
    } catch (cause) {
      if (abort.signal.aborted) return
      if (hasApiStatus(cause, 401)) return expired()
      setError(hasApiStatus(cause, 429) ? t.rateLimited :
        hasApiStatus(cause, 409) ? t.restartPreviewStale : t.restartPlanError)
    } finally {
      pending.current = null
      if (!abort.signal.aborted) setBusy(false)
    }
  }

  async function save(signal: AbortSignal) {
    let tag: string | null = null
    const path = '/resources/' + encodeURIComponent(resource.id) + '/docker/containers/' + encodeURIComponent(container.id)
    const value = await request<Draft>(path + '/restart-drafts', {
      csrf, signal, body: { confirm_stateless_test: true },
      onHeaders: headers => { tag = headers.get('ETag') },
    })
    const baseline = value.baseline
    if (!isUlid(value.id) || value.revision !== 1 || !tag || !/^[0-9a-f]{64}$/.test(value.plan_hash) ||
        value.action !== 'docker.restart' || value.diff?.operation !== 'RESTART' ||
        value.diff.configuration !== 'UNCHANGED' || baseline?.target?.id !== container.id ||
        baseline.target.resource_id !== resource.id || baseline.target.project !== container.project ||
        baseline.target.service !== container.service || baseline.target.state !== 'RUNNING' ||
        baseline.boot_id !== sample.boot_id || baseline.started_at !== container.started_at ||
        baseline.observed_at !== sample.observed_at || baseline.resource_revision !== resource.revision ||
        baseline.policy_revision !== resource.policy_revision) {
      throw new ApiError(409)
    }
    return { id: value.id, revision: value.revision, hash: value.plan_hash, tag, key: crypto.randomUUID(), savedAt: performance.now() }
  }

  async function prepare(signal: AbortSignal) {
    const saved = draft ?? await save(signal)
    if (signal.aborted) return
    setDraft(saved)
    const path = '/change-plans/' + saved.id
    const headers = { csrf, ifMatch: saved.tag, idempotencyKey: saved.key, signal }
    // The server records drafts and observations in whole seconds.
    const delay = Math.max(0, 1000 - (performance.now() - saved.savedAt))
    if (delay) await new Promise(resolve => window.setTimeout(resolve, delay))
    if (signal.aborted) return
    const id = probe ?? (await request<{ id: string }>(path + '/preflight', { ...headers, body: {} })).id
    if (!isUlid(id)) throw new Error()
    if (signal.aborted) return
    setProbe(id)
    for (let read = 0; read < 30 && !signal.aborted; read++) {
      const job = await request<{ status: string }>('/jobs/' + id, { signal })
      if (signal.aborted) return
      if (['FAILED', 'UNKNOWN_OUTCOME', 'CANCELLED_SAFE'].includes(job.status)) return setDecision('failed')
      if (job.status === 'SUCCEEDED') {
        const result = await request<{ backup_gate: string }>(path + '/backup-decision', {
          ...headers, body: { probe_id: id, request_key: saved.key },
        })
        if (!signal.aborted) setDecision(result.backup_gate === 'BACKUP_NOT_REQUIRED' ? 'passed' : 'denied')
        return
      }
      await new Promise(resolve => window.setTimeout(resolve, 2000))
    }
    if (!signal.aborted) setError(t.restartWaitLonger)
  }

  async function enqueue(approved: string, signal: AbortSignal) {
    if (!draft || !evidence) return
    const result = await request<{ id: string }>(plan + '/execution-requests', {
      ...options, signal, body: { ...evidence, approval_id: approved },
    })
    if (!isUlid(result.id)) throw new Error()
    if (signal.aborted) return
    setOperation(result.id)
    window.location.hash = restartHash({ planId: draft.id, revision: draft.revision, operationId: result.id })
  }

  return <div className="restart-plan">
    {!draft && <label><input type="checkbox" checked={confirmed} disabled={busy}
      onChange={event => confirm(event.target.checked)}/> {t.restartStateless}</label>}
    {draft && <p>{t.restartRevision} {draft.revision} · {t.restartDiff}</p>}
    {decision === 'waiting' && (
      busy ? <p role="status">{t.restartChecking}</p> :
      <button type="button" disabled={!confirmed} onClick={() => void run(prepare)}>
        {probe ? t.restartCheckResult : t.restartDraft}
      </button>
    )}
    {decision === 'failed' && <p role="alert" className="error">{t.probeFailed}</p>}
    {decision === 'denied' && <p role="alert" className="error">{t.restartBackupDenied}</p>}
    {decision === 'passed' && <p>{t.restartBackupPassed}</p>}
    {evidence && decision === 'passed' && !approval && <form onSubmit={event => {
      event.preventDefault()
      if (!password || busy) return
      const value = password
      setPassword('')
      void run(async signal => {
        const grant = await request<{ id: string }>('/auth/reauth', { csrf, signal, body: { password: value, plan_hash: draft?.hash } })
        if (signal.aborted) return
        if (!isUlid(grant.id)) throw new Error()
        const result = await request<{ approval_id: string }>(plan + '/approval', {
          ...options, signal, body: { ...evidence, reauth_id: grant.id },
        })
        if (!isUlid(result.approval_id)) throw new Error()
        if (signal.aborted) return
        setApproval(result.approval_id)
        await enqueue(result.approval_id, signal)
      })
    }}>
      <label>{t.restartPassword}<input type="password" autoComplete="current-password" required value={password}
        disabled={busy} onChange={event => setPassword(event.target.value)}/></label>
      <button disabled={!password || busy}>{t.restartApprove}</button>
    </form>}
    {approval && !operation && <button type="button" disabled={busy} onClick={() => void run(signal => enqueue(approval, signal))}>
      {t.restartExecute}
    </button>}
    {operation && draft && <a href={restartHash({ planId: draft.id, revision: draft.revision, operationId: operation })}>
      {t.restartTimeline}
    </a>}
    {error && <p role="alert" className="error">{error}</p>}
  </div>
}
