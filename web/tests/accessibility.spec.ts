import { expect, test } from '@playwright/test'
import type { Locator, Page } from '@playwright/test'
import { copy } from '../src/copy'

async function tabTo(page: Page, control: Locator) {
  await expect(control).toBeVisible()
  for (let step = 0; step < 30; step++) {
    if (await control.evaluate(element => element === document.activeElement)) return
    await page.keyboard.press('Tab')
  }
  await expect(control).toBeFocused()
}

for (const language of ['en', 'ru'] as const) {
  const t = copy[language]
  test.describe(language, () => {
    test.use({ locale: language === 'ru' ? 'ru-RU' : 'en-US' })

    test('keyboard navigation and text warnings across core WebUI screens', async ({ page }) => {
      await page.context().setExtraHTTPHeaders({
        'X-Forwarded-For': language === 'en' ? '2001:db8:1::1' : '2001:db8:1::2',
      })
      await page.goto('/')
      await expect(page.locator('html')).toHaveAttribute('lang', language)
      await expect(page.getByRole('heading', { name: t.signIn })).toBeVisible()

      await page.keyboard.press('Tab')
      await expect(page.getByRole('link', { name: t.skip })).toBeFocused()
      await page.keyboard.press('Enter')
      const main = page.getByRole('main')
      await expect(main).toBeFocused()

      const username = page.getByLabel(t.username, { exact: true })
      const password = page.getByLabel(t.password, { exact: true })
      await page.keyboard.press('Tab')
      await expect(username).toBeFocused()
      await page.keyboard.type('fixture-owner')
      await page.keyboard.press('Tab')
      await expect(password).toBeFocused()
      await page.keyboard.type('incorrect fixture password')
      await page.keyboard.press('Enter')
      await expect(main.getByRole('alert')).toHaveText(t.loginError)
      await expect(password).toHaveValue('')
      await expect(password).toBeFocused()
      await page.keyboard.type('HostOrbit fixture password!')
      await page.keyboard.press('Enter')
      await expect(main.getByRole('heading', { name: t.inventory })).toBeVisible()

      const stale = main.getByRole('button', { name: /01JCYQZ4T9V8MNVYEH3D2M7Q1B/ })
      await tabTo(page, stale)
      await page.keyboard.press('Enter')
      await expect(stale).toHaveAttribute('aria-pressed', 'true')
      const detail = main.getByRole('region', { name: t.detail })
      await expect(detail.getByText(t.unknown, { exact: true }).first()).toBeVisible()
      await expect(detail.getByText(t.stale, { exact: true })).toBeVisible()

      const navigation = main.getByRole('navigation', { name: t.navigation })
      const audit = navigation.getByRole('button', { name: t.audit, exact: true })
      await tabTo(page, audit)
      await page.keyboard.press('Enter')
      await expect(audit).toHaveAttribute('aria-current', 'page')
      await expect(main.getByRole('heading', { name: t.audit })).toBeVisible()

      const settings = navigation.getByRole('button', { name: t.settings, exact: true })
      await tabTo(page, settings)
      await page.keyboard.press('Enter')
      const timeZone = main.getByRole('combobox', { name: t.timeZone })
      await tabTo(page, timeZone)
      await page.keyboard.press('End')
      await expect(timeZone).toHaveValue('UTC')

      await tabTo(page, page.getByRole('button', { name: t.signOut }))
      await page.keyboard.press('Enter')
      await expect(main.getByRole('heading', { name: t.signIn })).toBeVisible()
    })
  })
}
