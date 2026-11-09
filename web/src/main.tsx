import { useCallback, useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { createRoot } from 'react-dom/client'
import { ApiError, observationState, request } from './api'
import type { InventoryPage, Presence, Resource, Session, Status } from './api'
import { copy } from './copy'
import type { Copy, Language } from './copy'
import { ProbeControl } from './probe'
import './style.css'

type Theme = 'system' | 'light' | 'dark'

function preference(key: string) {
  try { return localStorage.getItem(key) } catch { return null }
}

function savePreference(key: string, value: string) {
  try { localStorage.setItem(key, value) } catch { /* Preferences remain in memory. */ }
}

function Mark() {
  return <svg viewBox="0 0 32 32" width="30" height="30" aria-hidden="true">
    <circle cx="16" cy="16" r="7" fill="none" stroke="currentColor" strokeWidth="2"/>
    <ellipse cx="16" cy="16" rx="14" ry="6" transform="rotate(-40 16 16)" fill="none" stroke="currentColor" strokeWidth="2"/>
    <circle cx="24" cy="7" r="2" fill="currentColor"/>
  </svg>
}

function message(error: unknown, t: Copy) {
  return error instanceof ApiError && error.status === 429 ? t.rateLimited : t.requestError
}

function Login({ t, onLogin }: { t: Copy; onLogin: (session: Session) => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const values = new FormData(form)
    const password = form.elements.namedItem('password') as HTMLInputElement
    password.value = ''
    setError(null)
    setBusy(true)
    try {
      onLogin(await request<Session>('/auth/login', {
        body: { username: values.get('username'), password: values.get('password') },
      }))
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return <main id="main" className="auth-layout">
    <section className="login panel" aria-labelledby="sign-in-heading">
      <div className="login-icon"><Mark/></div>
      <h1 id="sign-in-heading">{t.signIn}</h1>
      <p>{t.loginHint}</p>
      <form onSubmit={submit} aria-busy={busy}>
        <label>{t.username}<input name="username" autoComplete="username" minLength={3} maxLength={64} required /></label>
        <label>{t.password}<input name="password" type="password" autoComplete="current-password" maxLength={128} required /></label>
        {error != null && <p role="alert" className="error">
          {error instanceof ApiError && (error.status === 401 || error.status === 403) ? t.loginError : message(error, t)}
        </p>}
        <button className="primary" type="submit" disabled={busy}>{busy ? t.loading : t.signIn}</button>
      </form>
    </section>
  </main>
}

function StatusBadge({ status, t }: { status: Status; t: Copy }) {
  return <span className="status" data-status={status}>
    <span className="dot" aria-hidden="true"/>
    {status === 'REACHABLE' ? t.reachable : status === 'NOT_CHECKED' ? t.notChecked : t.unknown}
  </span>
}

function statusReason(reason: string, t: Copy) {
  switch (reason) {
    case 'PROBE_SUCCEEDED': return t.statusCurrent
    case 'NO_COMPLETED_OBSERVATION': return t.noObservation
    case 'OBSERVATION_STALE': return t.stale
    case 'OBSERVATION_SCOPE_CHANGED': return t.scopeChanged
    case 'RESOURCE_DISABLED': return t.inactive
    case 'OBSERVATION_INVALID':
    case 'OBSERVATION_TIME_INVALID': return t.invalid
    default: return t.probeFailed
  }
}

function Detail({ resource, t, lang, now }: { resource: Resource; t: Copy; lang: Language; now: number }) {
  const observation = resource.observation
  const current = observationState(observation, now)
  const time = (seconds: number | null | undefined) => seconds == null ? '—' :
    new Intl.DateTimeFormat(lang, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(seconds * 1000))
  const presence = (value: Presence) => value === 'PRESENT' ? t.present : value === 'NOT_DETECTED' ? t.notDetected : t.unknown
  const software = observation.last_success?.software
  const docker = observation.last_success?.docker

  return <>
    <div className="detail-id"><span>{t.host}</span><code>{resource.id}</code></div>
    <div className="health">
      <StatusBadge status={current.status} t={t}/>
      <p>{statusReason(current.reason, t)}</p>
    </div>
    <dl className="facts">
      <div><dt>{t.lastCheck}</dt><dd>{time(observation.last_checked_at)}</dd></div>
      <div><dt>{t.lastSuccess}</dt><dd>{time(observation.last_success?.observed_at)}</dd></div>
      <div><dt>{t.since}</dt><dd>{time(resource.created_at)}</dd></div>
      <div><dt>{t.policy}</dt><dd>{resource.policy_revision}</dd></div>
    </dl>
    {observation.last_success && <div className="software">
      <h3>{t.observedSoftware}</h3>
      {software ? <>
        <p>{t.softwareHint}</p>
        <dl>
          <div><dt>Docker</dt><dd>{presence(software.docker)}</dd></div>
          <div><dt>Nginx</dt><dd>{presence(software.nginx)}</dd></div>
        </dl>
      </> : <p>{t.noSoftware}</p>}
    </div>}
    {docker && <div className="software">
      <h3>{t.dockerHeading}</h3>
      <p>{current.status === 'REACHABLE' ? t.dockerScope : t.dockerHistorical}</p>
      {docker.status === 'OBSERVED' ? <ul className="docker-list">
        {docker.containers.map(container => <li key={container.id}>
          <div><strong>{container.project} / {container.service}</strong><code title={container.id}>{container.id.slice(0, 12)}</code></div>
          <span className="pill">{t.containerState[container.state]}</span>
        </li>)}
      </ul> : <p>{t.dockerStatus[docker.status]}</p>}
    </div>}
  </>
}

function Inventory({ t, lang, expired, session }: { t: Copy; lang: Language; expired: () => void; session: Session }) {
  const [cursors, setCursors] = useState([''])
  const [revision, refresh] = useState(0)
  const [page, setPage] = useState<InventoryPage | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [detail, setDetail] = useState<Resource | null>(null)
  const [detailError, setDetailError] = useState<unknown>(null)
  const [now, setNow] = useState(Date.now)
  const after = cursors[cursors.length - 1]
  const reload = useCallback(() => refresh(value => value + 1), [])
  const current = page && detail?.id === selected ? detail : null

  useEffect(() => {
    const start = performance.now()
    const wallStart = Date.now()
    const timer = window.setInterval(() => {
      const elapsed = performance.now() - start
      setNow(previous => Math.max(previous, Date.now(), wallStart + elapsed))
    }, 1000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    const abort = new AbortController()
    setPage(null)
    setError(null)
    request<InventoryPage>('/resources?limit=25' + (after ? '&after=' + encodeURIComponent(after) : ''), { signal: abort.signal })
      .then(result => {
        if (abort.signal.aborted) return
        setPage(result)
        setSelected(current => result.items.some(item => item.id === current) ? current : result.items[0]?.id ?? null)
      })
      .catch(err => {
        if (abort.signal.aborted) return
        if (err instanceof ApiError && err.status === 401) expired()
        else { setError(err); setSelected(null) }
      })
    return () => abort.abort()
  }, [after, revision, expired])

  useEffect(() => {
    const abort = new AbortController()
    setDetail(null)
    setDetailError(null)
    if (selected) {
      request<Resource>('/resources/' + encodeURIComponent(selected), { signal: abort.signal })
        .then(result => { if (!abort.signal.aborted) setDetail(result) })
        .catch(err => {
          if (abort.signal.aborted) return
          if (err instanceof ApiError && err.status === 401) expired()
          else setDetailError(err)
        })
    }
    return () => abort.abort()
  }, [selected, revision, expired])

  return <main id="main" className="workspace">
    <div className="heading">
      <div><p className="eyebrow">{t.workspace}</p><h1>{t.inventory}</h1><p>{t.subtitle}</p></div>
      <button onClick={reload} disabled={!page && error == null}>
        <span aria-hidden="true">↻</span> {t.refresh}
      </button>
    </div>
    <div className="columns">
      <section className="panel hosts" aria-labelledby="host-heading">
        <div className="panel-heading">
          <h2 id="host-heading">{t.registered}</h2>
          {page && <span className="pill" title={t.pageTotal}>{page.items.length}</span>}
        </div>
        {error != null ? <p className="notice error" role="alert">{message(error, t)}</p> :
          page == null ? <p className="notice" role="status">{t.loading}</p> :
          page.items.length === 0 ? <p className="notice">{t.empty}</p> :
          <ul className="host-list">
            {page.items.map(item => <li key={item.id}>
              <button className="host-row" aria-pressed={selected === item.id} onClick={() => setSelected(item.id)}>
                <span className="host-icon" aria-hidden="true">▤</span>
                <span className="host-label"><code>{item.id}</code><StatusBadge status={observationState(item.observation, now).status} t={t}/></span>
                <span className="chevron" aria-hidden="true">›</span>
              </button>
            </li>)}
          </ul>}
        {(cursors.length > 1 || page?.next_after) && <div className="pager">
          <button disabled={cursors.length < 2 || page == null} onClick={() => setCursors(values => values.slice(0, -1))}>{t.previous}</button>
          <button disabled={!page?.next_after} onClick={() => {
            const next = page?.next_after
            if (next) setCursors(values => [...values, next])
          }}>{t.next}</button>
        </div>}
      </section>
      <section className="panel detail" aria-labelledby="detail-heading">
        <div className="panel-heading"><h2 id="detail-heading">{t.detail}</h2><span className="pill">{t.readOnly}</span></div>
        {detailError != null ? <p className="notice error" role="alert">
          {detailError instanceof ApiError && [403, 404].includes(detailError.status) ? t.missing : message(detailError, t)}
        </p> : current ? <Detail resource={current} t={t} lang={lang} now={now}/> :
          <p className="notice" role="status">{selected && !error ? t.loading : t.select}</p>}
        <ProbeControl resource={current} session={session} t={t} expired={expired} reload={reload}/>
      </section>
    </div>
  </main>
}

function App() {
  const [lang, setLang] = useState<Language>(() => {
    const stored = preference('hostorbit.language')
    if (stored === 'ru' || stored === 'en') return stored
    return navigator.language.toLowerCase().startsWith('ru') ? 'ru' : 'en'
  })
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = preference('hostorbit.theme')
    return stored === 'light' || stored === 'dark' ? stored : 'system'
  })
  const [session, setSession] = useState<Session | null>(null)
  const [restoring, setRestoring] = useState(true)
  const [sessionError, setSessionError] = useState<unknown>(null)
  const [retry, setRetry] = useState(0)
  const [ending, setEnding] = useState(false)
  const t = copy[lang]
  const expired = useCallback(() => { setSession(null); setSessionError(null) }, [])

  useEffect(() => {
    document.documentElement.lang = lang
    document.documentElement.dataset.theme = theme
  }, [lang, theme])

  useEffect(() => {
    const abort = new AbortController()
    setRestoring(true)
    setSessionError(null)
    request<Session>('/auth/session', { signal: abort.signal })
      .then(value => { if (!abort.signal.aborted) setSession(value) })
      .catch(err => {
        if (!abort.signal.aborted && !(err instanceof ApiError && err.status === 401)) setSessionError(err)
      })
      .finally(() => { if (!abort.signal.aborted) setRestoring(false) })
    return () => abort.abort()
  }, [retry])

  async function signOut() {
    if (!session || ending) return
    setEnding(true)
    setSessionError(null)
    try {
      await request<void>('/auth/logout', { body: {}, csrf: session.csrf_token })
      expired()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) expired()
      else setSessionError(err)
    } finally {
      setEnding(false)
    }
  }

  return <>
    <a className="skip" href="#main">{t.skip}</a>
    <header className="topbar">
      <div className="brand"><Mark/><span>HostOrbit</span></div>
      <div className="preferences">
        <select aria-label={t.language} value={lang} onChange={event => {
          const value = event.target.value as Language
          setLang(value)
          savePreference('hostorbit.language', value)
        }}><option value="en">English</option><option value="ru">Русский</option></select>
        <select aria-label={t.theme} value={theme} onChange={event => {
          const value = event.target.value as Theme
          setTheme(value)
          savePreference('hostorbit.theme', value)
        }}><option value="system">{t.system}</option><option value="light">{t.light}</option><option value="dark">{t.dark}</option></select>
        {session && <div className="account">
          <span>{session.user.username}</span>
          <button onClick={signOut} disabled={ending}>{t.signOut}</button>
        </div>}
      </div>
    </header>
    {restoring ? <main id="main" className="workspace" role="status">{t.loading}</main> :
      session ? <>
        {sessionError != null && <p className="session-error error" role="alert">{message(sessionError, t)}</p>}
        <Inventory key={session.user.id} t={t} lang={lang} expired={expired} session={session}/>
      </> : sessionError != null ? <main id="main" className="workspace">
        <p role="alert" className="error">{message(sessionError, t)}</p>
        <button onClick={() => setRetry(value => value + 1)}>{t.retry}</button>
      </main> : <Login t={t} onLogin={setSession}/>}
  </>
}

createRoot(document.getElementById('root')!).render(<App/>)
