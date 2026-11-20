import { useEffect, useState, type FormEvent } from 'react'
import { hasApiStatus, request, type Session } from './api'
import type { Copy } from './copy'

export function Enrollment({ t, session, expired, onEnroll, firstVps }: {
  t: Copy; session: Session; firstVps: boolean; expired: () => void; onEnroll: (id: string) => void
}) {
  const [busy, setBusy] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const [byId, setById] = useState(false)
  const [authentication, setAuthentication] = useState<'password' | 'private_key'>('password')
  const [candidates, setCandidates] = useState<string[] | null>(null)
  useEffect(() => {
    if (!byId || (!expanded && !firstVps)) return
    const abort = new AbortController()
    request<{ items: string[] }>('/enrollment/candidates', { signal: abort.signal })
      .then(({ items }) => { if (!abort.signal.aborted) setCandidates(items) })
      .catch(error => { if (!abort.signal.aborted && hasApiStatus(error, 401)) expired() })
    return () => abort.abort()
  }, [byId, expanded, expired, firstVps])
  const [status, setStatus] = useState<'enrollmentSuccess' | 'enrollmentMismatch' | 'enrollmentMissing' | 'enrollmentConflict'
    | 'enrollmentAuthenticationFailed' | 'enrollmentConnectionFailed' | 'enrollmentInvalid' | 'requestError' | null>(null)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const data = new FormData(form)
    const fingerprint = String(data.get('fingerprint')).trim()
    const resourceId = byId ? String(data.get('id')).trim() : null
    const credential = form.elements.namedItem(authentication)
    const body = byId ? { resource_id: resourceId, fingerprint } : {
      ip: String(data.get('ip')).trim(), port: Number(data.get('port')), username: String(data.get('username')).trim(),
      fingerprint, [authentication]: data.get(authentication),
    }
    if (credential instanceof HTMLInputElement || credential instanceof HTMLTextAreaElement) credential.value = ''
    data.delete(authentication)
    setBusy(true)
    setStatus(null)
    try {
      const result = await request<{ id: string }>(byId ? '/resources' : '/enrollment/ssh', {
        body, csrf: session.csrf_token,
      })
      if (byId && result.id !== resourceId) throw new Error('Unexpected resource')
      form.reset()
      setStatus('enrollmentSuccess')
      setCandidates(previous => previous?.filter(id => id !== result.id) ?? null)
      onEnroll(result.id)
    } catch (error) {
      if (hasApiStatus(error, 401)) expired()
      else if (hasApiStatus(error, 412)) setStatus('enrollmentMismatch')
      else if (hasApiStatus(error, 404)) setStatus('enrollmentMissing')
      else if (hasApiStatus(error, 409)) setStatus('enrollmentConflict')
      else if (hasApiStatus(error, 422)) setStatus('enrollmentInvalid')
      else if (hasApiStatus(error, 424)) setStatus('enrollmentAuthenticationFailed')
      else if (hasApiStatus(error, 502)) setStatus('enrollmentConnectionFailed')
      else setStatus('requestError')
    } finally {
      setBusy(false)
    }
  }

  return <details className="panel enrollment" open={firstVps || undefined}
    onToggle={event => setExpanded(event.currentTarget.open)}>
    <summary>{t.enroll}</summary>
    <form onSubmit={submit}>
      <p>{t.enrollmentHelp} <a href="https://github.com/RoyMan810/VPN-Orbit/blob/main/docs/stage1-installation.md#подготовка-vps-по-паролю-или-ssh-ключу">{t.enrollmentGuide}</a></p>
      {byId ? (candidates?.length ? <label>{t.enrollmentId}
        <select name="id" required defaultValue={candidates.length === 1 ? candidates[0] : ''}>
          {candidates.length > 1 && <option value="">{t.enrollmentChoose}</option>}
          {candidates.map(id => <option key={id} value={id}>{id}</option>)}
        </select>
      </label> : <label>{t.enrollmentId}<input name="id" required maxLength={26} pattern="[0-7][0-9A-HJKMNP-TV-Z]{25}"/></label>) : <>
        <label>{t.enrollmentIp}<input name="ip" required maxLength={45} autoComplete="off" spellCheck={false}/></label>
        <label>{t.enrollmentPort}<input name="port" type="number" min={1} max={65535} required defaultValue={22}/></label>
        <label>{t.enrollmentUsername}<input name="username" required maxLength={64} autoComplete="off" spellCheck={false}/></label>
        <label>{t.enrollmentAuthentication}<select value={authentication} disabled={busy}
          onChange={event => setAuthentication(event.currentTarget.value === 'private_key' ? 'private_key' : 'password')}>
          <option value="password">{t.enrollmentPassword}</option>
          <option value="private_key">{t.enrollmentPrivateKey}</option>
        </select></label>
        {authentication === 'password'
          ? <label>{t.enrollmentPassword}<input name="password" type="password" required maxLength={1024} autoComplete="off" disabled={busy}/></label>
          : <label>{t.enrollmentPrivateKey}<textarea name="private_key" required maxLength={8192} autoComplete="off" spellCheck={false} rows={5} disabled={busy}/></label>}
      </>}
      {byId && candidates?.length === 0 && status !== 'enrollmentSuccess' && <p>{t.enrollmentNoCandidates}</p>}
      <label>{t.enrollmentPin}<input name="fingerprint" required maxLength={50} placeholder="SHA256:…" autoComplete="off" spellCheck={false}/></label>
      <button disabled={busy}>{t.enrollmentSubmit}</button>
      {status && <p role="status">{t[status]}</p>}
      <button type="button" className="quiet" disabled={busy} onClick={() => { setById(!byId); setStatus(null) }}>
        {byId ? t.enrollmentUseSsh : t.enrollmentUseId}
      </button>
    </form>
  </details>
}
