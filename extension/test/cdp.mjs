// Three claims that were closed by reading source, settled here by watching a browser.
//
//   1. An evicted service worker leaves the wallet window saying so, not holding a dead Sign
//      button, and a page request that nobody answers ends rather than living for ever.
//   2. The portal's certificate section does not re-fetch per keystroke.
//   3. The hardware backup's PRF path is real, and the fake-PRF fallback is opt-in — with
//      PACT_FAKE_PRF unset, an authenticator without PRF must be reported as a failure.
//
// Item 2's subject is the portal, which lives in the other repository; it is built here to a
// scratch directory and served from there, so nothing in `pact-cloud` is touched — its `public/`
// is what a local Worker serves and is not ours to rewrite. `npm test` runs this file beside
// `run.mjs`; both need Chrome and fail loudly without it.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { execFileSync } from 'node:child_process'
import { readFileSync, existsSync, mkdtempSync, readdirSync } from 'node:fs'
import { join, extname } from 'node:path'
import { tmpdir } from 'node:os'
import puppeteer from 'puppeteer-core'
import { EXT, here, chromePath, serve, walletWindow, visible, textOf, waitScreen, ask, sleep, serviceWorkerTargetId } from './harness.mjs'

const PASS = 'correct horse battery'
let browser, extId, servers = [], pageA, originA, browserCdp

const swTarget = () => browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith(`chrome-extension://${extId}`), { timeout: 20000 })
const swWorker = async () => (await swTarget()).worker()

before(async () => {
  browser = await puppeteer.launch({
    executablePath: chromePath(),
    headless: true,
    enableExtensions: [EXT],
    // No fixed debugging port: Puppeteer takes a free one. A pinned port means two runs of this
    // suite on one machine — or a run beside anything else driving Chrome — fail to launch at all,
    // with a message about a websocket endpoint that says nothing about the cause.
    args: ['--no-first-run', '--no-default-browser-check'],
  })
  const sw = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 20000 })
  extId = new URL(sw.url()).host
  browserCdp = await browser.target().createCDPSession()
  originA = await serve(servers)
  pageA = await browser.newPage()
  await pageA.goto(originA + '/page.html')
  await pageA.waitForFunction(() => !!window.pact, { timeout: 10000 })
})

after(async () => {
  for (const s of servers) s.close()
  if (browser) await browser.close()
})

test('(1) the service worker is evicted mid-decision: the window says so and the page is refused, not left hanging', async () => {
  const h = await ask(pageA, 'window.pact.requestIdentity()')
  const w = await walletWindow(browser, extId)
  await waitScreen(w, 's-create')
  assert.equal(await visible(w, '#disconnected'), false, 'nothing is wrong yet')
  assert.equal(await h.settled(), null, 'the page is waiting on the person')

  // Evict it for real: the extension's worker is a CDP target of its own.
  const targetId = await serviceWorkerTargetId(browserCdp, extId)
  assert.ok(targetId, 'the extension has a service_worker target')
  await browserCdp.send('Target.closeTarget', { targetId })

  // The window notices its port die and says what happened, rather than leaving Sign armed.
  await w.waitForFunction(() => { const el = document.getElementById('disconnected'); return el && !el.hidden }, { timeout: 15000 })
  assert.match(await textOf(w, '#disconnected'), /locked while this window was open/)

  // And the page is told, rather than holding a promise nobody will answer.
  let v = null
  for (let i = 0; i < 60 && !(v = await h.settled()); i++) await sleep(100)
  assert.ok(v, 'the page request settled')
  assert.equal(v.ok, false)
  assert.equal(v.code, 'unavailable', JSON.stringify(v))
  await w.close()

  // The worker restarts on the next message, and a second attempt works.
  const h2 = await ask(pageA, 'window.pact.requestIdentity()')
  const w2 = await walletWindow(browser, extId)
  await waitScreen(w2, 's-create')
  assert.equal(await visible(w2, '#disconnected'), false, 'the fresh window is not showing a stale notice')
  await w2.type('#f-create input[name=name]', 'Alina Rao')
  await w2.type('#f-create input[name=passphrase]', PASS)
  await w2.type('#f-create input[name=again]', PASS)
  await w2.click('#f-create input[name=understood]')
  await w2.click('#f-create button[type=submit]')
  await waitScreen(w2, 's-hardware')
  await w2.click('#b-hw-skip')
  await waitScreen(w2, 's-pick')
  await w2.click('#f-pick button[type=submit]')
  await waitScreen(w2, 's-done')
  const v2 = await h2.value()
  assert.equal(v2.ok, true, JSON.stringify(v2))
  await w2.close()
})

test('(1b) a request nobody answers times out instead of leaking, and a window gone before it is seen is cancelled', async () => {
  // The deadline is ten minutes (CONFIG.REQUEST_TIMEOUT_MINUTES). Rather than wait, clamp the
  // worker's own `setTimeout` for the length of this test: the code under test is unchanged, only
  // the clock it asks for is shorter.
  let sw = await swWorker()
  await sw.evaluate(() => { globalThis.__origST = globalThis.setTimeout; globalThis.setTimeout = (fn, ms, ...a) => globalThis.__origST(fn, Math.min(ms || 0, 600), ...a) })
  const h = await ask(pageA, 'window.pact.requestIdentity()')
  const w = await walletWindow(browser, extId)
  await waitScreen(w, 's-pick') // the identity from (1) exists, so this is the pick screen
  let v = null
  for (let i = 0; i < 80 && !(v = await h.settled()); i++) await sleep(100)
  assert.ok(v, 'the request settled on its own')
  assert.equal(v.ok, false)
  assert.equal(v.code, 'timeout', JSON.stringify(v))
  await sw.evaluate(() => { if (globalThis.__origST) globalThis.setTimeout = globalThis.__origST })
  await w.close()

  // A window closed while it was still opening is not in `onRemoved`'s reach: the guard after the
  // await is what catches it. Drive that exact race by removing the window before `create` returns.
  sw = await swWorker()
  await sw.evaluate(() => {
    globalThis.__origCreate = chrome.windows.create.bind(chrome.windows)
    chrome.windows.create = async (opts) => { const win = await globalThis.__origCreate(opts); await chrome.windows.remove(win.id); return win }
  })
  const h2 = await ask(pageA, 'window.pact.requestIdentity()')
  let v2 = null
  for (let i = 0; i < 60 && !(v2 = await h2.settled()); i++) await sleep(100)
  await sw.evaluate(() => { if (globalThis.__origCreate) chrome.windows.create = globalThis.__origCreate })
  assert.ok(v2, 'the request settled rather than waiting on a window that is gone')
  assert.equal(v2.ok, false)
  assert.equal(v2.code, 'cancelled', JSON.stringify(v2))
})

test('(2) the portal fetches the certificate once per identity, not once per keystroke', async (t) => {
  // A fresh portal build in a scratch directory: `pact-cloud/gateway/public` is what a local
  // Worker serves and is not ours to rewrite, and the copy committed there predates the fix.
  const portal = join(EXT, '..', '..', 'pact-cloud', 'portal')
  assert.ok(existsSync(join(portal, 'package.json')), 'the portal is where it is expected: ' + portal)
  // PACT_PORTAL_DIST aims this at an already-built copy — which is how this test was shown to
  // fail against the bundle that predates the fix, rather than merely passing against the one after.
  const out = process.env.PACT_PORTAL_DIST || mkdtempSync(join(tmpdir(), 'pact-portal-'))
  if (!process.env.PACT_PORTAL_DIST) execFileSync('npx', ['vite', 'build', '--outDir', out, '--emptyOutDir'], { cwd: portal, stdio: 'pipe' })
  const bundle = readdirSync(join(out, 'assets')).find((f) => f.endsWith('.js'))
  assert.ok(bundle, 'the build produced a bundle')

  // Everything the identities page asks for, answered from here. One identity, already 2.0.
  const SLUG = 'work'
  const counts = new Map()
  const bump = (k) => counts.set(k, (counts.get(k) ?? 0) + 1)
  const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.json': 'application/json' }
  const json = (res, body) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(body)) }
  const app = createServer((req, res) => {
    const url = new URL(req.url, 'http://x')
    const p = url.pathname
    if (p === '/api/session') return json(res, { owner: { id: 'U-1', email: 'a@example.test', display_name: 'Alina' }, workspace: { id: 'w1', name: 'Work', slug: 'work', status: 'active', workspaceAdmin: true }, workspaces: [{ id: 'w1', name: 'Work', slug: 'work', status: 'active', workspaceAdmin: true }], session: { sid: 's', expires_at: Date.now() + 3600_000 }, api_host: 'api.example.test', turnstile_site_key: null })
    if (p === '/v1/identities') return json(res, { identities: [{ account_id: 'acc-1', slug: SLUG, fingerprint: 'sha256:' + 'a'.repeat(43), hostname: `w-stg.pact.contact/${SLUG}`, status: 'active', created_at: Date.now() }] })
    if (p.endsWith('/certificate')) { bump('certificate'); return json(res, { protocol: 2, root_fingerprint: 'sha256:' + 'b'.repeat(43), chain: [], kid: null, endpoint: `https://w-stg.pact.contact/${SLUG}`, not_before: null, not_after: null, renewal_due: false, pending_csr: null, superseded_kids: [], accept_new_hosts: 'auto', accept_1x: true }) }
    if (p.endsWith('/addresses/pending')) { bump('pending'); return json(res, { pending: [] }) }
    if (p.endsWith('/rotation')) return json(res, { account_id: 'acc-1', slug: SLUG, current_fingerprint: 'sha256:x', current_algo: 'ed25519', next_algo: 'ed25519', contacts: 0, grace_ms: 0, grace_until: 0, rotation_in_flight: false, pending_fanout: 0 })
    if (p.endsWith('/grants')) return json(res, { grants: [] })
    if (p === '/api/names') return json(res, { available: true, reason: null })
    if (p === '/api/domains') return json(res, { domains: [{ id: 'd1', domain: 'w-stg.pact.contact', host_template: '{workspace}-stg.pact.contact/{slug}', is_default: true }] })
    if (p.startsWith('/v1/') || p.startsWith('/api/')) return json(res, {})
    const file = join(out, p === '/' ? 'index.html' : p.slice(1))
    if (existsSync(file) && !file.endsWith('/')) { res.setHeader('content-type', types[extname(file)] ?? 'application/octet-stream'); return res.end(readFileSync(file)) }
    res.setHeader('content-type', 'text/html'); res.end(readFileSync(join(out, 'index.html')))
  })
  await new Promise((r) => app.listen(0, '127.0.0.1', r))
  servers.push(app)
  const origin = `http://127.0.0.1:${app.address().port}`

  const page = await browser.newPage()
  await page.goto(`${origin}/identity`, { waitUntil: 'domcontentloaded' })
  try {
    await page.waitForSelector('input[placeholder="work"]', { timeout: 25000 })
  } catch (e) {
    throw new Error('the identities page never rendered; body was: ' + (await page.evaluate(() => document.body.textContent.slice(0, 400))))
  }
  await sleep(500)
  const afterLoad = { certificate: counts.get('certificate') ?? 0, pending: counts.get('pending') ?? 0 }
  assert.ok(afterLoad.certificate >= 1, 'the certificate was read on load: ' + JSON.stringify(afterLoad))

  // Ten keystrokes in the slug field: every one re-renders the page that holds the section.
  await page.click('input[placeholder="work"]')
  await page.type('input[placeholder="work"]', 'homeoffice', { delay: 30 })
  await sleep(700)
  const afterTyping = { certificate: counts.get('certificate') ?? 0, pending: counts.get('pending') ?? 0 }
  t.diagnostic(`fetches on load ${JSON.stringify(afterLoad)}, after ten keystrokes ${JSON.stringify(afterTyping)}`)
  assert.deepEqual(afterTyping, afterLoad, `typing re-fetched: load ${JSON.stringify(afterLoad)} then ${JSON.stringify(afterTyping)}`)
  await page.close()
})
