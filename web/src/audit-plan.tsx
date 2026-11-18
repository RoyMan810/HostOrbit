import { useEffect, useState } from 'react'
import { hasApiStatus, isUlid, request } from './api'
import type { Copy } from './copy'

export interface AuditPlanRef {
  id: string
  revision: number
  resource: string
  hash?: string
  operation?: string
}

interface PlanDetail {
  plan: {
    id: string; revision: number; plan_hash: string; action: string; risk: string
    diff: { operation: string; configuration: string }
    baseline: { target: { id: string; resource_id: string; project: string; service: string } }
  }
  backup_decision: { gate: 'BACKUP_NOT_REQUIRED' | 'BACKUP_GATE_DENIED'; reason: string } | null
  operation: { id: string; status: keyof Copy['restartStates']; reason: string | null } | null
}

export function AuditPlan({ source, t, expired }: { source: AuditPlanRef; t: Copy; expired: () => void }) {
  const [open, setOpen] = useState(false)
  const [detail, setDetail] = useState<PlanDetail | null>(null)
  const [error, setError] = useState(false)
  const { id, revision, resource, hash, operation } = source
  useEffect(() => {
    if (!open) return
    const abort = new AbortController()
    async function load() {
      try {
        const value = await request<PlanDetail>(`/audit/change-plans/${id}/revisions/${revision}`, { signal: abort.signal })
        const plan = value.plan
        if (plan.id !== id || plan.revision !== revision || plan.baseline.target.resource_id !== resource ||
            !/^[0-9a-f]{64}$/.test(plan.plan_hash) || (hash && plan.plan_hash !== hash) ||
            (operation && value.operation?.id !== operation) || plan.action !== 'docker.restart' ||
            plan.diff.operation !== 'RESTART' || plan.diff.configuration !== 'UNCHANGED' ||
            plan.risk !== 'TEMPORARY_SERVICE_INTERRUPTION' || !/^[0-9a-f]{64}$/.test(plan.baseline.target.id) ||
            (value.operation !== null && (!isUlid(value.operation.id) || !Object.hasOwn(t.restartStates, value.operation.status))) ||
            (value.backup_decision !== null && !['BACKUP_NOT_REQUIRED', 'BACKUP_GATE_DENIED'].includes(value.backup_decision.gate))) {
          throw new Error()
        }
        if (!abort.signal.aborted) setDetail(value)
      } catch (cause) {
        if (abort.signal.aborted) return
        if (hasApiStatus(cause, 401)) expired()
        else setError(true)
      }
    }
    void load()
    return () => abort.abort()
  }, [open, id, revision, resource, hash, operation, expired, t.restartStates])

  return <div>
    <button type="button" aria-expanded={open} onClick={() => {
      setDetail(null)
      setError(false)
      setOpen(!open)
    }}>{open ? t.auditPlanClose : t.auditPlanOpen}</button>
    {open && (error ? <p role="alert">{t.auditPlanUnavailable}</p> : !detail ? <p role="status">{t.loading}</p> :
      <section aria-label={t.auditPlan}>
        <p>{t.restartRevision} {detail.plan.revision} · <code>{detail.plan.action}</code></p>
        <dl className="audit-facts">
          <div><dt>{t.probeTarget}</dt><dd><code>{resource}</code></dd></div>
          <div><dt>{t.auditContainer}</dt><dd>{detail.plan.baseline.target.project} / {detail.plan.baseline.target.service}
            <br/><code>{detail.plan.baseline.target.id}</code></dd></div>
          <div><dt>{t.auditPlanDiff}</dt><dd>{t.restartDiff}</dd></div>
          <div><dt>{t.auditPlanRisk}</dt><dd>{t.restartPreviewRisk}</dd></div>
          <div><dt>{t.auditPlanBackup}</dt><dd>{detail.backup_decision ?
            <>{detail.backup_decision.gate === 'BACKUP_NOT_REQUIRED' ? t.restartBackupPassed : t.restartBackupDenied}
              {' '}<code>{detail.backup_decision.reason}</code></> : t.auditBackupPending}</dd></div>
          <div><dt>{t.auditPlanOutcome}</dt><dd>{detail.operation ?
            <>{t.restartStates[detail.operation.status]} {detail.operation.reason && <code>{detail.operation.reason}</code>}</> :
            t.auditExecutionPending}</dd></div>
        </dl>
        <details><summary>{t.auditPlanSnapshot}</summary><pre tabIndex={0}>{JSON.stringify(detail.plan, null, 2)}</pre></details>
      </section>)}
  </div>
}
