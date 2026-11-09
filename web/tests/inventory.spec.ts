import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

const fresh = '01JCYQZ4T9V8MNVYEH3D2M7Q1A'
const stale = '01JCYQZ4T9V8MNVYEH3D2M7Q1B'
const never = '01JCYQZ4T9V8MNVYEH3D2M7Q1C'
const password = 'HostOrbit fixture password!'

async function signIn(page: Page, username = 'fixture-owner') {
  await page.goto('/')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'VPS inventory' })).toBeVisible()
}

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
