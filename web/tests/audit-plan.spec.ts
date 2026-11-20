import { expect, test } from '@playwright/test'

const resource = '01JCYQZ4T9V8MNVYEH3D2M7Q1A'
const planId = '01JCYQZ4T9V8MNVYEH3D2M7Q1D'
const operation = '01JCYQZ4T9V8MNVYEH3D2M7Q1E'
const hash = 'b'.repeat(64)
const target = { resource_id: resource, id: 'a'.repeat(64), project: 'fixture', service: 'web' }

for (const lang of ['en', 'ru'] as const) {
  test(`audit displays only a matching saved plan in ${lang}`, async ({ page }) => {
    const ru = lang === 'ru'
    const show = ru ? 'Показать сохранённый план' : 'Show saved plan'
    const hide = ru ? 'Скрыть сохранённый план' : 'Hide saved plan'
    const unavailable = ru ? 'Эта ревизия плана недоступна.' : 'This plan revision is unavailable.'
    await page.route('**/auth/session', route => route.fulfill({ json: {
      user: { id: planId, username: 'fixture-owner', role: 'Owner' }, csrf_token: 'fixture',
    } }))
    await page.route('**/api/v1/enrollment/candidates', route => route.fulfill({ json: { items: [] } }))
    await page.route('**/api/v1/resources?*', route => route.fulfill({ json: { items: [], next_after: null } }))
    await page.route('**/api/v1/audit?*', route => route.fulfill({ json: { items: [
      { seq: 17, event: { event: 'change_plan.draft_saved', outcome: 'SUCCEEDED', at: 1700000000,
        correlation_id: planId, target_id: resource, actor_id: 'owner', details: { revision: 2, plan_hash: hash } } },
    ] } }))
    const plan = { id: planId, revision: 2, plan_hash: hash, action: 'docker.restart', risk: 'TEMPORARY_SERVICE_INTERRUPTION',
      diff: { operation: 'RESTART', configuration: 'UNCHANGED' }, baseline: { target } }
    const path = '**/api/v1/audit/change-plans/' + planId + '/revisions/2'
    let revision = 2
    let reads = 0
    await page.route(path, route => {
      reads++
      return route.fulfill({ json: { plan: { ...plan, revision },
        backup_decision: { gate: 'BACKUP_NOT_REQUIRED', reason: 'RESTART_STATELESS_TEST_CONTAINER' },
        operation: { id: operation, status: 'UNKNOWN_OUTCOME', reason: 'SSH_RESTART_UNCONFIRMED' } } })
    })
    await page.goto('/')
    await page.getByLabel('Language').selectOption(lang)
    await page.getByRole('button', { name: ru ? 'Журнал аудита' : 'Audit log', exact: true }).click()
    await expect(page.getByRole('button', { name: show })).toBeVisible()
    expect(reads).toBe(0)
    await page.getByRole('button', { name: show }).press('Enter')
    const view = page.getByRole('region', { name: ru ? 'План изменений' : 'Change plan', exact: true })
    await expect(view).toContainText('fixture / web')
    await expect(view).toContainText(target.id)
    await expect(view).toContainText(ru ? 'Перезапуск контейнера с текущей конфигурацией.' : 'Restart this container with its current configuration.')
    await expect(view).toContainText('RESTART_STATELESS_TEST_CONTAINER')
    await expect(view).toContainText(ru ? 'Исход неизвестен.' : 'Outcome unknown.')
    await expect(view).toContainText('SSH_RESTART_UNCONFIRMED')
    await view.locator('summary').click()
    expect(JSON.parse(await view.locator('pre').innerText())).toEqual(plan)
    await page.getByRole('button', { name: hide }).click()
    revision++
    await page.getByRole('button', { name: show }).click()
    await expect(page.getByRole('alert')).toHaveText(unavailable)
    await expect(view).toHaveCount(0)
    await page.getByRole('button', { name: hide }).click()
    await page.route(path, route => route.fulfill({ status: 404, json: { code: 'RESOURCE_NOT_FOUND' } }))
    await page.getByRole('button', { name: show }).click()
    await expect(page.getByRole('alert')).toHaveText(unavailable)
    await expect(view).toHaveCount(0)
  })
}
