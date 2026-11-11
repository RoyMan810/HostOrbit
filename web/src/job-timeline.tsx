import { useEffect, useRef, useState } from 'react'
import { ApiError, request } from './api'
import type { Copy, Language } from './copy'

interface TimelineItem { seq: number; at: number; status: keyof Copy['probeStatus']; reason: string | null }

export function JobTimeline({ jobId, t, lang, expired, describedBy }: {
  jobId: string; t: Copy; lang: Language; expired: () => void; describedBy?: string
}) {
  const [items, setItems] = useState<TimelineItem[] | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState(false)
  const requestAbort = useRef<AbortController | null>(null)
  useEffect(() => () => requestAbort.current?.abort(), [])

  async function load() {
    if (requestAbort.current) return
    const abort = new AbortController()
    requestAbort.current = abort
    setItems(null)
    setError(null)
    setLoading(true)
    try {
      const result = await request<{ items: TimelineItem[] }>('/jobs/' + encodeURIComponent(jobId) + '/timeline', { signal: abort.signal })
      if (!abort.signal.aborted) setItems(result.items)
    } catch (err) {
      if (abort.signal.aborted) return
      if (err instanceof ApiError && err.status === 401) expired()
      else setError(err)
    } finally {
      if (!abort.signal.aborted) { requestAbort.current = null; setLoading(false) }
    }
  }

  return <div className="probe-timeline">
    <button onClick={() => void load()} disabled={loading} aria-describedby={describedBy}>{t.timelineLoad}</button>
    {loading && <p role="status">{t.loading}</p>}
    {error != null && <p className="error" role="alert">{error instanceof ApiError && [403, 404].includes(error.status) ? t.probeUnavailable : t.requestError}</p>}
    {items && (items.length === 0 ? <p>{t.timelineEmpty}</p> : <ol>
      {items.map(item => <li key={item.seq}>
        <time dateTime={new Date(item.at * 1000).toISOString()}>{new Intl.DateTimeFormat(lang, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(item.at * 1000))}</time>
        {' — '}<span>{t.probeStatus[item.status]}</span>{item.reason && <> <code>{item.reason}</code></>}
      </li>)}
    </ol>)}
  </div>
}
