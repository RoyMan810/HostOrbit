export interface Session {
  user: { id: string; username: string; role: 'Owner' | 'Admin' | 'Operator' | 'Auditor' }
  csrf_token: string
}

export type Status = 'REACHABLE' | 'NOT_CHECKED' | 'UNKNOWN'
export type Presence = 'PRESENT' | 'NOT_DETECTED' | 'UNKNOWN'
export type ContainerState = 'CREATED' | 'RESTARTING' | 'RUNNING' | 'REMOVING' | 'PAUSED' | 'EXITED' | 'DEAD' | 'UNKNOWN' | 'NOT_FOUND'
export interface DockerContainer {
  id: string
  project: string
  service: string
  state: ContainerState
}
export interface DockerObservation {
  status: 'OBSERVED' | 'NOT_CONFIGURED' | 'POLICY_INVALID' | 'UNAVAILABLE'
  containers: DockerContainer[]
}
export interface DockerRestartPreview {
  version: 1
  action: 'docker.restart'
  status: 'PREVIEW_ONLY'
  target: DockerContainer & { resource_id: string }
  resource_revision: number
  policy_revision: number
  observed_at: number
  boot_id: string
  risk: 'TEMPORARY_SERVICE_INTERRUPTION'
}
export interface Observation {
  status: Status
  reason: string
  last_checked_at: number | null
  last_success: {
    observed_at: number
    boot_id: string
    software?: Record<'docker' | 'nginx', Presence>
    docker?: DockerObservation
  } | null
}
export interface Resource {
  id: string
  enabled: boolean
  access_mode: 'READ_ONLY'
  revision: number
  policy_revision: number
  created_at: number
  observation: Observation
}
export interface InventoryPage {
  items: Resource[]
  next_after: string | null
}

export class ApiError extends Error {
  constructor(readonly status: number) {
    super('Controller request failed')
  }
}

export async function request<T>(path: string, options: {
  signal?: AbortSignal
  body?: object
  csrf?: string
  idempotencyKey?: string
} = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (options.body) headers['Content-Type'] = 'application/json'
  if (options.csrf) headers['X-CSRF-Token'] = options.csrf
  if (options.idempotencyKey) headers['Idempotency-Key'] = options.idempotencyKey
  const response = await fetch('/api/v1' + path, {
    method: options.body ? 'POST' : 'GET',
    body: options.body ? JSON.stringify(options.body) : undefined,
    signal: options.signal,
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    headers,
  })
  if (!response.ok) throw new ApiError(response.status)
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export function observationState(observation: Observation, now: number): { status: Status; reason: string } {
  if (observation.status !== 'REACHABLE') return observation
  const timestamp = observation.last_success?.observed_at
  if (timestamp === undefined || now < timestamp * 1000) {
    return { status: 'UNKNOWN', reason: 'OBSERVATION_TIME_INVALID' }
  }
  if (now - timestamp * 1000 > 300_000) {
    return { status: 'UNKNOWN', reason: 'OBSERVATION_STALE' }
  }
  return observation
}
