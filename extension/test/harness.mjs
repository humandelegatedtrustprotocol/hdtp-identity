// What both browser suites need: finding Chrome, driving the wallet's window, and starting a
// call on a page so its settled value can be read later. `run.mjs` proves the wallet's flows;
// `cdp.mjs` proves the three claims that were written down but never observed in a browser.
import { createServer } from 'node:http'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { homedir } from 'node:os'

export const here = dirname(fileURLToPath(import.meta.url))
export const EXT = join(here, '..')
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

export function chromePath() {
  if (process.env.PUPPETEER_EXECUTABLE_PATH) return process.env.PUPPETEER_EXECUTABLE_PATH
  const base = join(homedir(), '.cache', 'puppeteer', 'chrome')
  if (existsSync(base)) {
    const versions = readdirSync(base).filter((d) => d.startsWith('mac_arm-') || d.startsWith('mac-') || d.startsWith('linux-')).sort()
    for (const v of versions.reverse()) {
      for (const rel of ['chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing', 'chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing', 'chrome-linux64/chrome']) {
        const p = join(base, v, rel)
        if (existsSync(p)) return p
      }
    }
  }
  for (const p of ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome']) if (existsSync(p)) return p
  throw new Error('no Chrome found; set PUPPETEER_EXECUTABLE_PATH')
}

/** The fixture page that carries `window.pact`, on its own origin. */
export function serve(servers) {
  const html = readFileSync(join(here, 'fixtures', 'page.html'))
  return new Promise((resolve) => {
    const s = createServer((req, res) => { res.setHeader('content-type', 'text/html; charset=utf-8'); res.end(html) })
    s.listen(0, '127.0.0.1', () => { servers.push(s); resolve(`http://127.0.0.1:${s.address().port}`) })
  })
}

/** The next wallet window the extension opens, once its shell has rendered. */
export async function walletWindow(browser, extId) {
  const t = await browser.waitForTarget((t) => t.type() === 'page' && t.url().startsWith(`chrome-extension://${extId}/window.html`) && (t.__seen === undefined), { timeout: 15000 })
  t.__seen = true
  const p = await t.page()
  await p.waitForSelector('#main', { timeout: 10000 })
  return p
}

export const visible = (p, sel) => p.evaluate((s) => { const el = document.querySelector(s); return !!el && !el.hidden && el.offsetParent !== null }, sel)
export const textOf = (p, sel) => p.$eval(sel, (el) => el.textContent.trim())
export async function waitScreen(p, id) {
  await p.waitForFunction((s) => { const el = document.getElementById(s); return el && !el.hidden }, { timeout: 20000 }, id)
}

/** Starts a wallet call on a page and returns a handle to read its settled value later. */
export async function ask(page, expr) {
  const key = 'k' + Math.random().toString(36).slice(2, 8)
  await page.evaluate((k, e) => { window[k] = (0, eval)(e).then((r) => ({ ok: true, r }), (x) => ({ ok: false, code: x.code, message: x.message })) }, key, expr)
  return {
    settled: () => page.evaluate((k) => Promise.race([window[k], new Promise((r) => setTimeout(() => r(null), 50))]), key),
    value: () => page.evaluate((k) => window[k], key),
  }
}

/** The extension's service worker as a CDP target id, for the domains Puppeteer does not wrap. */
export async function serviceWorkerTargetId(browserCdp, extId) {
  const { targetInfos } = await browserCdp.send('Target.getTargets')
  const sw = targetInfos.find((t) => t.type === 'service_worker' && t.url.startsWith(`chrome-extension://${extId}`))
  return sw ? sw.targetId : null
}
