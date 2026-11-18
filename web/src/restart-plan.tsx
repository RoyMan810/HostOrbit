import { useEffect, useRef, useState } from 'react'
import { ApiError, isUlid, request } from './api'
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
      if (cause instanceof ApiError && cause.status === 401) return expired()
      setError(cause instanceof ApiError && cause.status === 429 ? t.rateLimited :
        cause instanceof ApiError && cause.status === 409 ? t.restartPreviewStale : t.restartPlanError)
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
    if (!signal.aborted) setDraft({ id: value.id, revision: value.revision, hash: value.plan_hash, tag, key: crypto.randomUUID(), savedAt: performance.now() })
  }

  return <div className="restart-plan">
    {!draft && <>
      <label><input type="checkbox" checked={confirmed} disabled={busy}
        onChange={event => confirm(event.target.checked)}/> {t.restartStateless}</label>
      <button type="button" disabled={!confirmed || busy} onClick={() => void run(save)}>{t.restartDraft}</button>
    </>}
    {draft && <p>{t.restartRevision} {draft.revision} · {t.restartDiff}</p>}
    {draft && !probe && <button type="button" disabled={busy} onClick={() => void run(async signal => {
      // The server timestamps drafts and observations to whole seconds.
      const delay = Math.max(0, 1000 - (performance.now() - draft.savedAt))
      if (delay) await new Promise(resolve => window.setTimeout(resolve, delay))
      if (signal.aborted) return
      const job = await request<{ id: string }>(plan + '/preflight', { ...options, signal, body: {} })
      if (!isUlid(job.id)) throw new Error()
      if (!signal.aborted) setProbe(job.id)
    })}>{t.restartPreflight}</button>}
    {evidence && decision === 'waiting' && <>
      <p role="status">{t.restartChecking}</p>
      <button type="button" disabled={busy} onClick={() => void run(async signal => {
        const job = await request<{ status: string }>('/jobs/' + probe, { signal })
        if (signal.aborted) return
        if (['FAILED', 'UNKNOWN_OUTCOME', 'CANCELLED_SAFE'].includes(job.status)) return setDecision('failed')
        if (job.status !== 'SUCCEEDED') return
        const value = await request<{ backup_gate: string }>(plan + '/backup-decision', { ...options, signal, body: evidence })
        if (!signal.aborted) setDecision(value.backup_gate === 'BACKUP_NOT_REQUIRED' ? 'passed' : 'denied')
      })}>{t.restartCheckResult}</button>
    </>}
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
        if (!signal.aborted) setApproval(result.approval_id)
      })
    }}>
      <label>{t.restartPassword}<input type="password" autoComplete="current-password" required value={password}
        disabled={busy} onChange={event => setPassword(event.target.value)}/></label>
      <button disabled={!password || busy}>{t.restartApprove}</button>
    </form>}
    {draft && evidence && approval && !operation && <button type="button" disabled={busy} onClick={() => void run(async signal => {
      const result = await request<{ id: string }>(plan + '/execution-requests', {
        ...options, signal, body: { ...evidence, approval_id: approval },
      })
      if (!isUlid(result.id)) throw new Error()
      if (signal.aborted) return
      setOperation(result.id)
      window.location.hash = restartHash({ planId: draft.id, revision: draft.revision, operationId: result.id })
    })}>{t.restartExecute}</button>}
    {operation && draft && <a href={restartHash({ planId: draft.id, revision: draft.revision, operationId: operation })}>
      {t.restartTimeline}
    </a>}
    {error && <p role="alert" className="error">{error}</p>}
  </div>
}
