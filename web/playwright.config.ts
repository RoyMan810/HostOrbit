import { defineConfig } from '@playwright/test'

const origin = 'https://127.0.0.1:4173'
const browser = process.env.HOSTORBIT_CHROMIUM

export default defineConfig({
  testDir: './tests',
  workers: 1,
  use: {
    baseURL: origin,
    ignoreHTTPSErrors: true,
    locale: 'en-US',
    launchOptions: browser ? { executablePath: browser } : undefined,
  },
  webServer: {
    command: 'python tests/fixture.py',
    url: origin + '/healthz',
    ignoreHTTPSErrors: true,
    reuseExistingServer: false,
  },
})
