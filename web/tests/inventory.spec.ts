import { readFile } from 'node:fs/promises'
import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

const fresh = '01JCYQZ4T9V8MNVYEH3D2M7Q1A'
const stale = '01JCYQZ4T9V8MNVYEH3D2M7Q1B'
const never = '01JCYQZ4T9V8MNVYEH3D2M7Q1C'
const password = 'HostOrbit fixture password!'

let clientNumber = 0
test.beforeEach(async ({ context }, { workerIndex }) => {
  // The loopback Controller fixture trusts the forwarded client IP.
  // Give each browser context its own login-rate bucket.
  const address = `2001:db8::${workerIndex.toString(16)}:${(++clientNumber).toString(16)}`
  await context.setExtraHTTPHeaders({ 'X-Forwarded-For': address })
})

async function signIn(page: Page, username = 'fixture-owner') {
  await page.goto('/')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'VPS inventory' })).toBeVisible()
}

test('checks audit integrity on demand and displays the latest result', async ({ page }) => {
  let checks = 0
  page.on('request', req => {
    if (new URL(req.url()).pathname === '/api/v1/audit/integrity') checks++
  })
  await signIn(page)
  await page.getByRole('button', { name: 'Audit log', exact: true }).click()
  await expect(page.getByText('auth.login', { exact: true }).first()).toBeVisible()
  expect(checks).toBe(0)
  await page.getByRole('button', { name: 'Check audit integrity' }).click()
  await expect(page.getByRole('status')).toHaveText('Audit and Outbox passed the integrity check.')
  await page.getByLabel('Language').selectOption('ru')
  await page.route('**/api/v1/audit/integrity', route => route.fulfill({ json: { status: 'invalid' } }), { times: 1 })
  const check = page.getByRole('button', { name: 'Проверить целостность журнала' })
  await check.click()
  await expect(page.getByRole('alert')).toHaveText('Обнаружено нарушение целостности журнала или Outbox.')
  await page.route('**/api/v1/audit/integrity', route => route.fulfill({ status: 503, json: {} }), { times: 1 })
  await check.click()
  await expect(page.getByRole('alert')).toHaveText('Не удалось выполнить проверку целостности.')
  expect(checks).toBe(3)
})

test('shows audit events only to authorised users and clears them on session loss', async ({ page, context }) => {
  await signIn(page)
  await page.getByRole('button', { name: 'Audit log', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Audit log' })).toBeVisible()
  await expect(page.getByText('auth.login', { exact: true }).first()).toBeVisible()
  await page.getByLabel('Language').selectOption('ru')
  await expect(page.getByRole('heading', { name: 'Журнал аудита' })).toBeVisible()
  await context.clearCookies()
  await page.getByRole('button', { name: 'Обновить журнал аудита' }).click()
  await expect(page.getByRole('button', { name: 'Войти' })).toBeVisible()
  await expect(page.getByText('auth.login', { exact: true })).toHaveCount(0)
})

test('loads an audit event’s linked SSH job timeline on demand and clears it on refresh', async ({ page }) => {
  const timelineRequests: string[] = []
  page.on('request', request => {
    if (request.url().endsWith('/timeline')) timelineRequests.push(request.url())
  })
  await signIn(page)
  await page.getByRole('button', { name: 'Audit log', exact: true }).click()
  const entries = page.locator('.audit-list > li')
  const accepted = entries.filter({ has: page.getByText('job.accepted', { exact: true }) }).first()
  const authentication = entries.filter({ has: page.getByText('auth.login', { exact: true }) }).first()
  await expect(accepted).toBeVisible()
  expect(timelineRequests).toEqual([])
  await expect(authentication.getByRole('button', { name: 'Show job history' })).toHaveCount(0)
  const showHistory = accepted.getByRole('button', { name: 'Show job history' })
  await expect(showHistory).toBeVisible()
  const job = (await accepted.locator('dd code').last().innerText()).trim()
  const response = page.waitForResponse(reply => reply.url().endsWith('/jobs/' + job + '/timeline'))
  await showHistory.press('Enter')
  const reply = await response
  expect(reply.request().method()).toBe('GET')
  expect(reply.status()).toBe(200)
  const history = accepted.getByRole('list')
  await expect(history.getByRole('listitem').first()).toContainText('Queued')
  await expect(history.getByRole('listitem').last()).toContainText('PROBE_VERIFIED')
  await page.getByLabel('Language').selectOption('ru')
  await expect(history.getByRole('listitem').first()).toContainText('В очереди')
  await page.getByRole('button', { name: 'Обновить журнал аудита' }).click()
  await expect(accepted.getByRole('button', { name: 'Показать историю задания' })).toBeVisible()
  await expect(history).toHaveCount(0)
  expect(timelineRequests).toHaveLength(1)
})

test('audit permission alone does not grant access to a linked SSH job timeline', async ({ page }) => {
  await signIn(page, 'fixture-auditor')
  await page.getByRole('button', { name: 'Audit log', exact: true }).click()
  const entry = page.locator('.audit-list > li').filter({ has: page.getByText('job.finished', { exact: true }) }).first()
  const showHistory = entry.getByRole('button', { name: 'Show job history' })
  await expect(showHistory).toBeVisible()
  const response = page.waitForResponse(reply => reply.url().endsWith('/timeline'))
  await showHistory.click()
  expect((await response).status()).toBe(404)
  await expect(entry.getByText('The job status is unavailable with your current access.')).toBeVisible()
  await expect(entry.getByRole('list')).toHaveCount(0)
})

test('downloads only the reviewed SSH audit export for the current page', async ({ page }) => {
  const canary = 'private-fixture-canary'
  await page.route('**/api/v1/audit?*', async route => {
    const response = await route.fetch()
    const result = await response.json()
    const accepted = result.items.find(item => item.event.event === 'job.accepted')
    accepted.event.details = { private: canary }
    result.items.push({
      seq: result.items.at(-1).seq + 1,
      event: { ...accepted.event, outcome: canary },
    })
    await route.fulfill({ response, json: result })
  })
  await signIn(page)
  await page.getByRole('button', { name: 'Audit log', exact: true }).click()
  const accepted = page.locator('.audit-list > li').filter({ has: page.getByText('job.accepted', { exact: true }) }).first()
  await expect(accepted).toBeVisible()
  const identifiers = await accepted.locator('dd code').allTextContents()

  const downloadLink = page.getByRole('link', { name: 'Download JSON' })
  await expect(downloadLink).toHaveCount(0)
  const review = page.getByText('Review SSH audit export', { exact: true })
  await expect(review).toBeVisible()
  await review.press('Enter')
  await expect(downloadLink).toBeVisible()
  const preview = page.locator('.audit-export pre')
  const reviewed = await preview.innerText()
  const { version, events } = JSON.parse(reviewed)
  expect(version).toBe(1)
  expect(events).toHaveLength(12)
  expect(events[0]).toEqual({ job: 1, event: 'job.accepted', outcome: 'QUEUED', at: expect.stringMatching(/Z$/) })
  expect(events[5]).toMatchObject({ job: 1, event: 'job.finished', outcome: 'SUCCEEDED' })
  expect(events[6]).toMatchObject({ job: 2, event: 'job.accepted' })
  for (const value of [...identifiers, canary, 'auth.login', 'details']) expect(reviewed).not.toContain(value)

  await page.getByLabel('Language').selectOption('ru')
  const ready = page.waitForEvent('download')
  await page.getByRole('link', { name: 'Скачать JSON' }).click()
  const download = await ready
  expect(download.suggestedFilename()).toBe('hostorbit-ssh-audit.json')
  expect(await readFile(await download.path(), 'utf8')).toBe(reviewed)
  await page.getByRole('button', { name: 'Обновить журнал аудита' }).click()
  await expect(page.getByText('Проверить экспорт SSH-аудита', { exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Скачать JSON' })).toHaveCount(0)
})

test('pages through the bounded audit API without retaining the previous page', async ({ page }) => {
  await signIn(page)
  await page.route('**/api/v1/audit?*', async route => {
    const after = Number(new URL(route.request().url()).searchParams.get('after'))
    const sequences = after === 0 ? Array.from({ length: 100 }, (_, index) => index + 1) : [101]
    await route.fulfill({ json: { items: sequences.map(seq => ({ seq, event: {
      at: 1700000000, actor_id: 'actor', event: `fixture.event.${seq}`,
      target_id: 'target', outcome: 'OK', correlation_id: 'correlation',
    } })) } })
  })
  await page.getByRole('button', { name: 'Audit log', exact: true }).click()
  await expect(page.getByText('fixture.event.1', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Next page' }).click()
  await expect(page.getByText('fixture.event.101', { exact: true })).toBeVisible()
  await expect(page.getByText('fixture.event.1', { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: 'Previous page' }).click()
  await expect(page.getByText('fixture.event.1', { exact: true })).toBeVisible()
})

test('shows the Controller denial for audit without permission', async ({ page }) => {
  await signIn(page, 'fixture-operator')
  await page.getByRole('button', { name: 'Audit log', exact: true }).click()
  await expect(page.getByRole('alert')).toHaveText('You do not have permission to read the audit log.')
})

test('authenticates against the real Controller and restores the browser session', async ({ page, context }) => {
  await signIn(page)
  const cookie = (await context.cookies()).find(c => c.name === '__Host-hostorbit_session')
  expect(cookie).toMatchObject({ httpOnly: true, secure: true, sameSite: 'Strict' })
  await page.reload()
  await expect(page.getByRole('heading', { name: 'VPS inventory' })).toBeVisible()
  expect(await page.evaluate(() => Object.keys(localStorage))).toEqual([])
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()
  expect((await context.cookies()).find(c => c.name === '__Host-hostorbit_session')).toBeUndefined()
})

test('distinguishes current SSH reachability, historical data and an unchecked VPS', async ({ page }) => {
  await signIn(page)
  const detail = page.getByRole('region', { name: 'VPS details' })
  await page.getByRole('button', { name: new RegExp(fresh) }).click()
  await expect(detail.getByText('Reachable over SSH', { exact: true })).toBeVisible()
  await expect(detail.getByText('Docker', { exact: true })).toBeVisible()
  await expect(detail.getByText('Present', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: new RegExp(stale) }).click()
  await expect(detail.getByText('Unknown', { exact: true })).toBeVisible()
  await expect(detail.getByText('Observation expired', { exact: true })).toBeVisible()
  await expect(detail.getByText('Last successful observation', { exact: true })).toBeVisible()
  await expect(detail.getByText('Docker', { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: new RegExp(never) }).click()
  await expect(detail.getByText('Not checked', { exact: true })).toBeVisible()
})

test('respects scoped inventory and clears it after the session is lost', async ({ page, context }) => {
  await signIn(page, 'fixture-operator')
  await expect(page.getByRole('button', { name: new RegExp(fresh) })).toBeVisible()
  await expect(page.getByText(stale, { exact: true })).toHaveCount(0)
  await context.clearCookies()
  await page.getByRole('button', { name: 'Refresh inventory' }).click()
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()
  await expect(page.getByText(fresh, { exact: true })).toHaveCount(0)
})

test('supports keyboard login, Russian labels and dark mode at mobile width', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/')
  await page.getByLabel('Username').fill('fixture-owner')
  await page.getByLabel('Username').press('Tab')
  await expect(page.getByLabel('Password')).toBeFocused()
  await page.getByLabel('Password').fill(password)
  await page.getByLabel('Password').press('Enter')
  await expect(page.getByRole('heading', { name: 'VPS inventory' })).toBeVisible()
  await page.getByLabel('Language').selectOption('ru')
  await expect(page.getByRole('heading', { name: 'Инвентарь VPS' })).toBeVisible()
  await page.getByLabel('Тема').selectOption('dark')
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390)
})

test('expires a previously reachable sample even after the browser clock moves back', async ({ page }) => {
  await page.clock.install()
  await signIn(page)
  const detail = page.getByRole('region', { name: 'VPS details' })
  await expect(detail.getByText('Reachable over SSH', { exact: true })).toBeVisible()
  await page.clock.setSystemTime(Date.now() - 3_600_000)
  await page.clock.fastForward(301_000)
  await expect(detail.getByText('Observation expired', { exact: true })).toBeVisible()
})

test('loads the next and previous cursor pages from the Controller', async ({ page }) => {
  // Keep the live test dataset small while exercising the server's real cursor.
  await page.route('**/api/v1/resources?*', route => {
    const url = new URL(route.request().url())
    url.searchParams.set('limit', '2')
    return route.continue({ url: url.href })
  })
  await signIn(page)
  await expect(page.getByRole('button', { name: new RegExp(fresh) })).toBeVisible()
  await expect(page.getByRole('button', { name: new RegExp(never) })).toHaveCount(0)
  await page.getByRole('button', { name: 'Next page' }).click()
  await expect(page.getByRole('button', { name: new RegExp(never) })).toBeVisible()
  await expect(page.getByRole('button', { name: new RegExp(fresh) })).toHaveCount(0)
  await page.getByRole('button', { name: 'Previous page' }).click()
  await expect(page.getByRole('button', { name: new RegExp(fresh) })).toBeVisible()
})

test('shows imported Docker state and labels it historical when the sample expires', async ({ page }) => {
  await page.clock.install()
  await signIn(page)
  const detail = page.getByRole('region', { name: 'VPS details' })
  await expect(detail.getByRole('heading', { name: 'Docker containers' })).toBeVisible()
  await expect(detail.getByText('fixture / web', { exact: true })).toBeVisible()
  await expect(detail.getByText('Running', { exact: true })).toBeVisible()
  await page.clock.fastForward(301_000)
  await expect(detail.getByText('Historical container observation.', { exact: true })).toBeVisible()
})

test('shows Docker host bindings, unavailable data and historical observations in both languages', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 })
  await page.clock.install()
  await signIn(page)
  const detail = page.getByRole('region', { name: 'VPS details' })
  const web = detail.getByRole('listitem').filter({ hasText: 'fixture / web' })
  const worker = detail.getByRole('listitem').filter({ hasText: 'fixture / worker' })
  const missing = detail.getByRole('listitem').filter({ hasText: 'fixture / missing' })
  await expect(web.getByText('Published host ports', { exact: true })).toBeVisible()
  await expect(web.getByText('127.0.0.1:8443 → 443/tcp', { exact: true })).toBeVisible()
  const ipv6 = '[2001:db8:abcd:1234:dead:beef:1234:5678]:5353 → 53/udp'
  await expect(web.getByText(ipv6, { exact: true })).toBeVisible()
  await expect(worker.getByText('No published host ports', { exact: true })).toBeVisible()
  await expect(missing.getByText('Port bindings unavailable', { exact: true })).toBeVisible()
  await page.getByLabel('Language').selectOption('ru')
  await expect(page.getByText('Опубликованные порты хоста', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Нет опубликованных портов хоста', { exact: true })).toBeVisible()
  await expect(page.getByText('Данные о привязках портов недоступны', { exact: true })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320)
  await page.clock.fastForward(301_000)
  await expect(page.getByText('Историческое наблюдение контейнеров.', { exact: true })).toBeVisible()
  await expect(page.getByText(ipv6, { exact: true })).toBeVisible()
})

test('treats the missing Docker v3 port field as unavailable', async ({ page }) => {
  await page.route('**/api/v1/resources/' + fresh, async route => {
    const response = await route.fetch()
    const resource = await response.json()
    for (const container of resource.observation.last_success.docker.containers) {
      delete container.published_ports
    }
    await route.fulfill({ response, json: resource })
  })
  await signIn(page)
  const detail = page.getByRole('region', { name: 'VPS details' })
  await expect(detail.getByText('Port bindings unavailable', { exact: true })).toHaveCount(3)
  await expect(detail.getByText('No published host ports', { exact: true })).toHaveCount(0)
})

test('opens a Docker restart preview through the real Controller and clears it on expiry', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.clock.install()
  await signIn(page)
  const button = page.getByRole('button', { name: 'Preview restart for fixture / web' })
  const response = page.waitForResponse(reply => reply.url().endsWith('/restart-preview'))
  await button.press('Enter')
  const reply = await response
  expect(reply.request().method()).toBe('GET')
  expect(reply.status()).toBe(200)
  expect(new URL(reply.url()).pathname).toBe('/api/v1/resources/' + fresh + '/docker/containers/' + 'a'.repeat(64) + '/restart-preview')
  await expect(page.getByText('Preview only. No restart was scheduled.')).toBeVisible()
  await expect(page.getByText('A restart can briefly interrupt this service.')).toBeVisible()
  await expect(page.getByText('a'.repeat(64), { exact: true })).toBeVisible()
  await expect(button).toHaveAccessibleDescription('a'.repeat(12))
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390)
  await page.clock.fastForward(301_000)
  await expect(button).toHaveCount(0)
  await expect(page.getByText('Preview only. No restart was scheduled.')).toHaveCount(0)
})

test('shows the real Controller denial when the operator lacks restart permission', async ({ page }) => {
  await signIn(page, 'fixture-operator')
  await page.getByRole('button', { name: 'Preview restart for fixture / web' }).click()
  await expect(page.getByRole('alert')).toHaveText('The Controller denied this preview.')
})

test('rejects a preview that belongs to a different observation', async ({ page }) => {
  await page.route('**/restart-preview', async route => {
    const response = await route.fetch()
    const preview = await response.json()
    await route.fulfill({ response, json: { ...preview, observed_at: preview.observed_at + 1 } })
  })
  await signIn(page)
  await page.getByRole('button', { name: 'Preview restart for fixture / web' }).click()
  await expect(page.getByRole('alert')).toHaveText('Refresh the inventory before requesting another preview.')
  await expect(page.getByText('Preview only. No restart was scheduled.')).toHaveCount(0)
})

async function finishProbe(page: Page, id: string, outcome: 'SUCCEEDED' | 'UNKNOWN_OUTCOME') {
  const response = await page.request.post('/__fixture__/jobs/' + id + '/finish', { params: { outcome } })
  expect(response.status()).toBe(204)
}

function acceptedProbe(page: Page) {
  return page.waitForResponse(response =>
    response.url().endsWith('/observations') && response.request().method() === 'POST' && response.status() === 202)
}

test('queues an authorised SSH check and refreshes the VPS after completion', async ({ page }) => {
  await signIn(page)
  await page.getByRole('button', { name: new RegExp(never) }).click()
  const detail = page.getByRole('region', { name: 'VPS details' })
  await expect(detail.getByText('Not checked', { exact: true })).toBeVisible()
  const accepted = acceptedProbe(page)
  await page.getByRole('button', { name: 'Run SSH check' }).click()
  const job = await (await accepted).json()
  expect(job.resource_id).toBe(never)
  await expect(page.getByText('Queued', { exact: true })).toBeVisible()
  await expect(page.getByText(job.id, { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Run SSH check' })).toBeDisabled()
  await page.getByRole('button', { name: 'Audit log', exact: true }).click()
  await page.getByRole('button', { name: 'VPS inventory', exact: true }).click()
  await expect(page.getByText(job.id, { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Run SSH check' })).toBeDisabled()
  await finishProbe(page, job.id, 'SUCCEEDED')
  await expect(page.getByText('Check completed', { exact: true })).toBeVisible()
  await expect(detail.getByText('Reachable over SSH', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Show job history' }).click()
  const history = page.locator('.probe-timeline')
  await expect(history.getByText('Queued', { exact: true })).toBeVisible()
  await expect(history.getByText('Check completed', { exact: true })).toBeVisible()
  await page.route('**/api/v1/jobs/*/timeline', route => route.fulfill({ status: 404, json: {} }), { times: 1 })
  await page.getByRole('button', { name: 'Show job history' }).click()
  await expect(history.getByText('The job status is unavailable with your current access.')).toBeVisible()
  await expect(history.getByText('Queued', { exact: true })).toHaveCount(0)
  const next = acceptedProbe(page)
  await page.getByRole('button', { name: 'Run SSH check' }).click()
  const nextJob = await (await next).json()
  expect(nextJob.id).not.toBe(job.id)
  await expect(history.getByText('The job status is unavailable with your current access.')).toHaveCount(0)
  await expect(history.locator('li')).toHaveCount(0)
  await finishProbe(page, nextJob.id, 'SUCCEEDED')
  await expect(page.getByText('Check completed', { exact: true })).toBeVisible()
})

test('reuses the original request and VPS after the accepted reply is lost', async ({ page }) => {
  await signIn(page)
  let original: { id: string; key: string } | undefined
  await page.route('**/api/v1/resources/' + fresh + '/observations', async route => {
    const response = await route.fetch()
    expect(response.status()).toBe(202)
    original = { id: (await response.json()).id, key: route.request().headers()['idempotency-key'] }
    await route.abort('failed')
  }, { times: 1 })
  await page.getByRole('button', { name: 'Run SSH check' }).click()
  await expect(page.getByText('Request confirmation is unavailable.', { exact: true })).toBeVisible()
  expect(original?.id).toBeTruthy()
  await page.getByRole('button', { name: new RegExp(stale) }).click()
  await expect(page.getByRole('region', { name: 'VPS details' }).getByText(stale, { exact: true })).toBeVisible()
  const accepted = acceptedProbe(page)
  await page.getByRole('button', { name: 'Retry the same request' }).click()
  const response = await accepted
  const job = await response.json()
  expect(job.resource_id).toBe(fresh)
  expect(job.id).toBe(original?.id)
  expect(response.request().headers()['idempotency-key']).toBe(original?.key)
  await finishProbe(page, job.id, 'SUCCEEDED')
  await expect(page.getByText('Check completed', { exact: true })).toBeVisible()
})

test('resumes reading the accepted job and preserves an unknown outcome', async ({ page }) => {
  await signIn(page)
  let submissions = 0
  page.on('request', request => {
    if (request.url().endsWith('/observations') && request.method() === 'POST') submissions += 1
  })
  await page.route('**/api/v1/jobs/*', route => route.abort('failed'), { times: 1 })
  const accepted = acceptedProbe(page)
  await page.getByRole('button', { name: 'Run SSH check' }).click()
  const job = await (await accepted).json()
  await expect(page.getByRole('button', { name: 'Check job status' })).toBeVisible()
  await expect(page.getByText('Outcome unknown', { exact: true })).toHaveCount(0)
  await finishProbe(page, job.id, 'UNKNOWN_OUTCOME')
  await page.getByRole('button', { name: 'Check job status' }).click()
  await expect(page.getByText('Outcome unknown', { exact: true })).toBeVisible()
  await expect(page.getByRole('region', { name: 'VPS details' }).getByText('Unknown', { exact: true })).toBeVisible()
  expect(submissions).toBe(1)
})

test('displays the Controller denial for an operator with read access only', async ({ page }) => {
  await signIn(page, 'fixture-operator')
  const denied = page.waitForResponse(response => response.url().endsWith('/observations') && response.status() === 403)
  await page.getByRole('button', { name: 'Run SSH check' }).click()
  await denied
  await expect(page.getByText('The Controller denied this SSH check.', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Retry the same request' })).toHaveCount(0)
})

test('a denied retry leaves the earlier acceptance uncertain and blocks a fresh key', async ({ page }) => {
  await signIn(page)
  let acceptedId = ''
  await page.route('**/api/v1/resources/' + fresh + '/observations', async route => {
    const response = await route.fetch()
    expect(response.status()).toBe(202)
    acceptedId = (await response.json()).id
    await route.abort('failed')
  }, { times: 1 })
  await page.getByRole('button', { name: 'Run SSH check' }).click()
  const retry = page.getByRole('button', { name: 'Retry the same request' })
  await expect(retry).toBeVisible()
  expect(acceptedId).toBeTruthy()
  const disabled = await page.request.post('/__fixture__/resources/' + fresh + '/disable')
  expect(disabled.status()).toBe(204)
  const denied = page.waitForResponse(response => response.url().endsWith('/observations') && response.status() === 404)
  await retry.click()
  await denied
  await expect(page.getByText('The retry was denied. The original request is still unconfirmed.', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: new RegExp(stale) }).click()
  await expect(page.getByRole('button', { name: 'Run SSH check' })).toBeDisabled()
  const original = await page.request.get('/api/v1/jobs/' + acceptedId)
  expect((await original.json()).status).toBe('QUEUED')
})
