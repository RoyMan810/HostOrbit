import { useEffect, useState, type FormEvent } from 'react'
import { hasApiStatus, request, type Session } from './api'
import type { Copy } from './copy'

export function Enrollment({ t, session, expired, onEnroll, firstVps }: {
  t: Copy; session: Session; firstVps: boolean; expired: () => void; onEnroll: (id: string) => void
}) {
  const [busy, setBusy] = useState(false)
  const [candidates, setCandidates] = useState<string[] | null>(null)
  useEffect(() => {
    const abort = new AbortController()
    request<{ items: string[] }>('/enrollment/candidates', { signal: abort.signal })
      .then(({ items }) => { if (!abort.signal.aborted) setCandidates(items) })
      .catch(error => { if (!abort.signal.aborted && hasApiStatus(error, 401)) expired() })
    return () => abort.abort()
  }, [expired])
  const [status, setStatus] = useState<'enrollmentSuccess' | 'enrollmentMismatch' | 'enrollmentMissing' | 'enrollmentConflict' | 'requestError' | null>(null)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const data = new FormData(form)
    const resource_id = String(data.get('id')).trim()
    setBusy(true)
    setStatus(null)
    try {
      const result = await request<{ id: string }>('/resources', {
        body: { resource_id, fingerprint: String(data.get('fingerprint')).trim() }, csrf: session.csrf_token,
      })
      if (result.id !== resource_id) throw new Error('Unexpected resource')
      form.reset()
      setStatus('enrollmentSuccess')
      setCandidates(previous => previous?.filter(id => id !== resource_id) ?? null)
      onEnroll(resource_id)
    } catch (error) {
      if (hasApiStatus(error, 401)) expired()
      else if (hasApiStatus(error, 412)) setStatus('enrollmentMismatch')
      else if (hasApiStatus(error, 404)) setStatus('enrollmentMissing')
      else if (hasApiStatus(error, 409)) setStatus('enrollmentConflict')
      else setStatus('requestError')
    } finally {
      setBusy(false)
    }
  }

  return <details className="panel enrollment" open={firstVps || undefined}>
    <summary>{t.enroll}</summary>
    <form onSubmit={submit}>
      <p>{t.enrollmentHelp} <a href="https://github.com/RoyMan810/HostOrbit/blob/main/docs/stage1-installation.md#подготовка-vps-по-паролю-или-ssh-ключу">{t.enrollmentGuide}</a></p>
      {candidates?.length ? <label>{t.enrollmentId}
        <select name="id" required defaultValue={candidates.length === 1 ? candidates[0] : ''}>
          {candidates.length > 1 && <option value="">{t.enrollmentChoose}</option>}
          {candidates.map(id => <option key={id} value={id}>{id}</option>)}
        </select>
      </label> : <label>{t.enrollmentId}<input name="id" required maxLength={26} pattern="[0-7][0-9A-HJKMNP-TV-Z]{25}"/></label>}
      {candidates?.length === 0 && status !== 'enrollmentSuccess' && <p>{t.enrollmentNoCandidates}</p>}
      <label>{t.enrollmentPin}<input name="fingerprint" required maxLength={50} placeholder="SHA256:…"/></label>
      <button disabled={busy}>{t.enrollmentSubmit}</button>
      {status && <p role="status">{t[status]}</p>}
    </form>
  </details>
}
