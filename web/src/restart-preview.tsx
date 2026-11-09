import { useEffect, useRef, useState } from 'react'
import { ApiError, request } from './api'
import type { DockerContainer, DockerRestartPreview, Observation, Resource } from './api'
import type { Copy } from './copy'

type Status = 'idle' | 'loading' | 'ready' | 'denied' | 'stale' | 'rateLimited' | 'error'

export function RestartPreview({ resource, container, sample, t, expired }: {
  resource: Resource
  container: DockerContainer
  sample: NonNullable<Observation['last_success']>
  t: Copy
  expired: () => void
}) {
  const [status, setStatus] = useState<Status>('idle')
  const pending = useRef<AbortController | null>(null)
  useEffect(() => () => pending.current?.abort(), [])

  async function loadPreview() {
    if (pending.current) return
    const abort = new AbortController()
    pending.current = abort
    setStatus('loading')
    const resourceId = encodeURIComponent(resource.id)
    const containerId = encodeURIComponent(container.id)
    try {
      const preview = await request<DockerRestartPreview>(
        `/resources/${resourceId}/docker/containers/${containerId}/restart-preview`,
        { signal: abort.signal },
      )
      if (abort.signal.aborted) return
      const matches = preview.version === 1 && preview.action === 'docker.restart' &&
        preview.status === 'PREVIEW_ONLY' && preview.risk === 'TEMPORARY_SERVICE_INTERRUPTION' &&
        preview.resource_revision === resource.revision && preview.policy_revision === resource.policy_revision &&
        preview.observed_at === sample.observed_at && preview.boot_id === sample.boot_id &&
        preview.target?.resource_id === resource.id && preview.target.id === container.id &&
        preview.target.project === container.project && preview.target.service === container.service &&
        preview.target.state === 'RUNNING'
      setStatus(matches ? 'ready' : 'stale')
    } catch (error) {
      if (abort.signal.aborted) return
      if (error instanceof ApiError) {
        if (error.status === 401) return expired()
        if (error.status === 403) return setStatus('denied')
        if (error.status === 404 || error.status === 409) return setStatus('stale')
        if (error.status === 429) return setStatus('rateLimited')
      }
      setStatus('error')
    } finally {
      pending.current = null
    }
  }

  return <div className="docker-preview">
    <button type="button" disabled={status === 'loading'} onClick={loadPreview}
      aria-label={`${t.restartPreviewFor} ${container.project} / ${container.service}`}
      aria-describedby={`docker-container-${container.id}`}>
      {status === 'loading' ? t.loading : t.restartPreview}
    </button>
    {status === 'ready' && <div className="docker-preview-result" role="status">
      <p>{t.restartPreviewOnly}</p>
      <p>{t.restartPreviewRisk}</p>
      <code>{container.id}</code>
    </div>}
    {status === 'denied' && <p role="alert" className="error">{t.restartPreviewDenied}</p>}
    {status === 'stale' && <p role="alert" className="error">{t.restartPreviewStale}</p>}
    {status === 'rateLimited' && <p role="alert" className="error">{t.rateLimited}</p>}
    {status === 'error' && <p role="alert" className="error">{t.requestError}</p>}
  </div>
}
