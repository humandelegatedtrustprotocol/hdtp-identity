// The extension driven end to end in Chrome: a page asks, the wallet's window decides, the page
// gets exactly what it asked for. Run with `npm test`; Chrome for Testing comes from
// PUPPETEER_EXECUTABLE_PATH or ~/.cache/puppeteer.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { createServer } from 'node:http'
import { readFileSync, readdirSync, existsSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { homedir } from 'node:os'
import puppeteer from 'puppeteer-core'
import { EXT, here, chromePath, serve as serveFixture, walletWindow as openWallet, visible, textOf, waitScreen, ask, sleep } from './harness.mjs'

const require = createRequire(import.meta.url)
const core = require('../../js/pkg-node/pact_identity_wasm.js')
const call = (name, args) => {
  const out = JSON.parse(core.call(name, JSON.stringify(args)))
  if (out && out.error && !('ok' in out)) throw new Error(`${name}: ${out.error}: ${out.why}`)
  return out
}

const PASS = 'correct horse battery'
const ENDPOINT_A = 'https://agent.alina.example/mcp'
const ENDPOINT_B = 'https://alina.pact.contact/alina/mcp'
let browser, extId, servers = [], pageA, pageB, originA, originB, downloads
const serve = () => serveFixture(servers)
const walletWindow = () => openWallet(browser, extId)

function newCsr(endpoint) {
  const host = call('generate_key', { alg: 'ed25519' })
  const { der } = call('csr_new', { cn: 'Alina Rao', host_pkcs8: host.pkcs8, endpoint })
  return { csr: der, host }
}

before(async () => {
  downloads = join(here, 'tmp', 'downloads')
  mkdirSync(downloads, { recursive: true })
  browser = await puppeteer.launch({
    executablePath: chromePath(),
    headless: true,
    enableExtensions: [EXT],
    args: ['--no-first-run', '--no-default-browser-check'],
  })
  const sw = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 20000 })
  extId = new URL(sw.url()).host
  const cdp = await browser.target().createCDPSession()
  await cdp.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: downloads, eventsEnabled: true })
  originA = await serve()
  originB = await serve()
  pageA = await browser.newPage()
  await pageA.goto(originA + '/page.html')
  await pageA.waitForFunction(() => !!window.pact, { timeout: 10000 })
})

after(async () => {
  for (const s of servers) s.close()
  if (browser) await browser.close()
})

test('window.pact is present and frozen; the page sees nothing else', async () => {
  const shape = await pageA.evaluate(() => ({ keys: Object.keys(window.pact).sort(), frozen: Object.isFrozen(window.pact), version: window.pact.version }))
  assert.deepEqual(shape.keys, ['__wallet', 'ceremony', 'issueCertificate', 'listCertificates', 'requestIdentity', 'syncContacts', 'version'])
  assert.equal(shape.frozen, true)
  const r = await pageA.evaluate(() => window.pact.listCertificates().then(() => 'ok', (e) => e.code))
  assert.equal(r, 'not_granted')
})

test('(1) requestIdentity: the person creates an identity in the wallet window and grants it', async () => {
  const h = await ask(pageA, 'window.pact.requestIdentity()')
  const w = await walletWindow()
  await waitScreen(w, 's-create')
  assert.equal(await h.settled(), null, 'nothing is answered before the person acts')
  await w.type('#f-create input[name=name]', 'Alina Rao')
  await w.type('#f-create input[name=passphrase]', PASS)
  await w.type('#f-create input[name=again]', PASS)
  await w.click('#f-create input[name=understood]')
  await w.click('#f-create button[type=submit]')
  await waitScreen(w, 's-hardware')
  await w.click('#b-hw-skip')
  await waitScreen(w, 's-pick')
  assert.equal(await textOf(w, '#pick-origin'), originA)
  assert.equal(await h.settled(), null, 'still pending until Allow')
  await w.click('#f-pick button[type=submit]')
  await waitScreen(w, 's-done')
  const v = await h.value()
  assert.equal(v.ok, true, JSON.stringify(v))
  assert.deepEqual(Object.keys(v.r).sort(), ['cn', 'root_fingerprint'])
  assert.equal(v.r.cn, 'Alina Rao')
  assert.match(v.r.root_fingerprint, /^sha256:[A-Za-z0-9_-]{43}$/)
  await sleep(500)
  const files = readdirSync(downloads).filter((f) => f.endsWith('.pact-vault.json'))
  assert.ok(files.length >= 1, 'the vault file was downloaded: ' + files.join(','))
  const vault = JSON.parse(readFileSync(join(downloads, files[0]), 'utf8'))
  assert.equal(vault.format, 'pact-vault/1')
  const { plaintext } = call('vault_open', { passphrase: PASS, vault })
  assert.equal(plaintext.roots[0].fingerprint, v.r.root_fingerprint)
  await w.close()
})

let firstChain
test('(2) issueCertificate: the window shows the endpoint, the passphrase is asked for a new address, Sign returns a valid chain', async () => {
  const { csr } = newCsr(ENDPOINT_A)
  const h = await ask(pageA, `window.pact.issueCertificate(${JSON.stringify(csr)})`)
  const w = await walletWindow()
  await waitScreen(w, 's-issue')
  assert.equal(await textOf(w, '#issue-endpoint'), ENDPOINT_A)
  assert.equal(await textOf(w, '#issue-origin'), originA)
  assert.equal(await visible(w, '#issue-newhost'), true, 'a host never issued to is flagged')
  assert.equal(await visible(w, '#issue-pass-wrap'), true, 'a new endpoint asks for the passphrase again')
  assert.equal(await h.settled(), null, 'nothing is signed before the click')
  await w.click('#b-sign')
  await waitScreen(w, 's-issue')
  await w.waitForFunction(() => document.getElementById('e-issue').textContent.length > 0, { timeout: 10000 })
  assert.match(await textOf(w, '#e-issue'), /passphrase/, 'an empty passphrase is refused')
  await w.type('#f-issue input[name=passphrase]', PASS)
  await w.click('#b-sign')
  await waitScreen(w, 's-done')
  const v = await h.value()
  assert.equal(v.ok, true, JSON.stringify(v))
  assert.deepEqual(Object.keys(v.r).sort(), ['chain', 'endpoint', 'not_after', 'not_before', 'root_fingerprint', 'warnings'])
  assert.equal(v.r.chain.length, 2)
  const check = call('validate_chain', { chain: v.r.chain, now: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), expected_endpoint: ENDPOINT_A, expected_root: v.r.root_fingerprint })
  assert.equal(check.ok, true, JSON.stringify(check))
  firstChain = v.r.chain
  const list = await pageA.evaluate(() => window.pact.listCertificates())
  assert.equal(list.certificates.length, 1)
  assert.equal(list.certificates[0].endpoint, ENDPOINT_A)
  assert.ok(!('pkcs8' in list.certificates[0]) && !JSON.stringify(list).includes('pkcs8'), 'no key material reaches the page')
  await w.close()
})

test('(3) a second live leaf at another address is refused without move; with move it is issued; a renewal needs the click alone', async () => {
  const { csr } = newCsr(ENDPOINT_B)
  const h = await ask(pageA, `window.pact.issueCertificate(${JSON.stringify(csr)})`)
  let w = await walletWindow()
  await waitScreen(w, 's-issue')
  assert.equal(await visible(w, '#issue-refused'), true)
  assert.match(await textOf(w, '#issue-refused'), /a second endpoint is a move/)
  assert.equal(await w.$eval('#b-sign', (b) => b.disabled), true)
  await w.waitForFunction(() => true)
  let v
  for (let i = 0; i < 40 && !(v = await h.settled()); i++) await sleep(100)
  assert.equal(v.ok, false)
  assert.equal(v.code, 'one_live_leaf')
  await w.close()

  const h2 = await ask(pageA, `window.pact.issueCertificate(${JSON.stringify(csr)}, { move: true })`)
  w = await walletWindow()
  await waitScreen(w, 's-issue')
  assert.equal(await visible(w, '#issue-move'), true)
  assert.equal(await visible(w, '#issue-pass-wrap'), true)
  await w.type('#f-issue input[name=passphrase]', PASS)
  await w.click('#b-sign')
  await waitScreen(w, 's-done')
  const v2 = await h2.value()
  assert.equal(v2.ok, true, JSON.stringify(v2))
  assert.equal(call('validate_chain', { chain: v2.r.chain, now: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), expected_endpoint: ENDPOINT_B }).ok, true)
  assert.equal(call('compare_leaves', { pinned: firstChain[0], presented: v2.r.chain[0] }).order, 'newer')
  await w.close()

  const renew = newCsr(ENDPOINT_B)
  const h3 = await ask(pageA, `window.pact.issueCertificate(${JSON.stringify(renew.csr)})`)
  w = await walletWindow()
  await waitScreen(w, 's-issue')
  assert.equal(await visible(w, '#issue-pass-wrap'), false, 'a renewal for a known endpoint asks for no passphrase')
  assert.equal(await visible(w, '#issue-refused'), false)
  await w.click('#b-sign')
  await waitScreen(w, 's-done')
  const v3 = await h3.value()
  assert.equal(v3.ok, true, JSON.stringify(v3))
  assert.equal(call('compare_leaves', { pinned: v2.r.chain[0], presented: v3.r.chain[0] }).order, 'newer')
  await w.close()
})

test('(4) the ceremony message signup from another origin is answered with a leaf', async () => {
  pageB = await browser.newPage()
  await pageB.goto(originB + '/page.html')
  await pageB.waitForFunction(() => !!window.pact, { timeout: 10000 })
  const endpoint = 'https://bharat.pact.contact/alina/mcp'
  const { csr } = newCsr(endpoint)
  await pageB.evaluate((m) => window.postMessage(m, '*'), { pact: 'ceremony/1', op: 'signup', csr, endpoint, display_name: 'Alina Rao', new_host: true })
  const w = await walletWindow()
  await waitScreen(w, 's-pick')
  assert.equal(await textOf(w, '#pick-origin'), originB)
  await w.click('#f-pick button[type=submit]')
  await waitScreen(w, 's-issue')
  assert.equal(await textOf(w, '#issue-title'), 'Issue the first certificate')
  assert.equal(await textOf(w, '#issue-endpoint'), endpoint)
  assert.equal(await visible(w, '#issue-refused'), true, 'the identity already has a live leaf elsewhere: a signup at a second address is a move')
  await sleep(300)
  let answers = await pageB.evaluate(() => window.__ceremony)
  assert.equal(answers.length, 1)
  assert.equal(answers[0].op, 'error')
  await w.close()

  await pageB.evaluate((m) => window.postMessage(m, '*'), { pact: 'ceremony/1', op: 'move', csr, endpoint, display_name: 'Alina Rao', new_host: true })
  const w2 = await walletWindow()
  await waitScreen(w2, 's-issue')
  await w2.type('#f-issue input[name=passphrase]', PASS)
  await w2.click('#b-sign')
  await waitScreen(w2, 's-done')
  await pageB.waitForFunction(() => window.__ceremony.length === 2, { timeout: 10000 })
  answers = await pageB.evaluate(() => window.__ceremony)
  assert.equal(answers[1].op, 'leaf')
  assert.equal(answers[1].chain.length, 2)
  assert.equal(call('validate_chain', { chain: answers[1].chain, now: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), expected_endpoint: endpoint }).ok, true)
  assert.equal(answers[1].root_fingerprint, call('parse_certificate', { der: answers[1].chain[1] }).fingerprint)
  await w2.close()
})

test('(4b) syncContacts shows every difference and applies only what is ticked', async () => {
  // A real root certificate, and the fingerprint it hashes to: a `root_cert` is worth exactly its
  // binding to the root the book pins, so the wallet checks the two agree before storing either.
  const bharat = call('generate_key', { alg: 'ed25519' })
  const bharatRoot = call('build_root', { cn: 'Bharat', pkcs8: bharat.pkcs8, not_before: new Date(Date.now() - 86400000).toISOString().replace(/\.\d+Z$/, 'Z') })
  const contacts = [{ root: bharatRoot.fingerprint, endpoint: 'https://b.example/mcp', name: 'Bharat', root_cert: bharatRoot.der }]
  const h = await ask(pageA, `window.pact.syncContacts(${JSON.stringify(contacts)})`)
  const w = await walletWindow()
  await waitScreen(w, 's-sync')
  assert.equal((await w.$$('#sync-list .item')).length, 1)
  assert.match(await textOf(w, '#sync-list'), /add Bharat/)
  await w.click('#f-sync button[type=submit]')
  await waitScreen(w, 's-done')
  const v = await h.value()
  assert.equal(v.ok, true)
  assert.equal(v.r.contacts.length, 1)
  assert.equal(v.r.contacts[0].root, contacts[0].root)
  // The root certificate the host holds rides into the book and back out under the name the portal reads.
  assert.equal(v.r.contacts[0].root_cert, contacts[0].root_cert)
  assert.equal(v.r.book[0].root_cert, contacts[0].root_cert)
  await w.close()
})

test('(4c) a root certificate that is not the pinned root\'s is refused, and nothing is stored', async () => {
  // A former host's own certificate under a friend's fingerprint: §14.5's poisoned archive, arriving
  // through the book instead. The wallet refuses it, says so, and writes nothing; the page's request
  // stays open, so the person can untick the row and apply again or decline.
  const stranger = call('generate_key', { alg: 'ed25519' })
  const strangerRoot = call('build_root', { cn: 'Not Bharat', pkcs8: stranger.pkcs8, not_before: new Date(Date.now() - 86400000).toISOString().replace(/\.\d+Z$/, 'Z') })
  const chenRoot = 'sha256:' + 'a'.repeat(43)
  const contacts = [{ root: chenRoot, endpoint: 'https://c.example/mcp', name: 'Chen', root_cert: strangerRoot.der }]
  const h = await ask(pageA, `window.pact.syncContacts(${JSON.stringify(contacts)})`)
  const w = await walletWindow()
  await waitScreen(w, 's-sync')
  await w.click('#f-sync button[type=submit]')
  await w.waitForFunction(() => document.getElementById('e-sync').textContent.length > 0, { timeout: 10000 })
  assert.match(await textOf(w, '#e-sync'), /not for the root this contact is pinned by/)
  assert.equal(await visible(w, '#f-sync'), true, 'the form stays open so the row can be unticked')
  assert.equal(await h.settled(), null, 'the page is still waiting, not answered')
  // Nothing was written: declining leaves the wallet's own book as (4b) left it.
  await w.click('#b-sync-deny')
  const v = await h.value()
  assert.equal(v.ok, false)
  const again = await ask(pageA, 'window.pact.syncContacts([])')
  const w2 = await walletWindow()
  await waitScreen(w2, 's-sync')
  const list = await textOf(w2, '#sync-list')
  assert.match(list, /remove Bharat/, 'Bharat from (4b) is still the book')
  assert.ok(!/Chen/.test(list), 'Chen was never stored')
  await w2.click('#b-sync-deny')
  await again.value().catch(() => {})
})

test('(5) hardware wrap: a PRF credential re-seals the vault and unlocks it after a lock', async (t) => {
  const w = await browser.newPage()
  try { w.target().__seen = true } catch {} // this page is the test's own window.html, not a wallet popup walletWindow() should return
  const cdp = await w.createCDPSession()
  let prf = 'virtual authenticator'
  await cdp.send('WebAuthn.enable', { enableUI: false })
  try {
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } })
  } catch (e) {
    prf = 'fake PRF (virtual authenticator without hasPrf: ' + e.message + ')'
  }
  await w.goto(`chrome-extension://${extId}/window.html`)
  await waitScreen(w, 's-home')
  await w.click('#b-backup-hw')
  // From home the wallet goes to the screen with the two doors rather than registering on the spot.
  // An unpinned registration is one a password manager can take from a security key, which is the
  // whole reason that screen has two buttons and home no longer has one.
  await waitScreen(w, 's-hardware')
  await w.click('#b-hw-device') // this virtual authenticator is `internal`: the platform door
  await w.waitForFunction(() => /enabled on this device|behind the vault/.test(document.getElementById('home-hw').textContent) || document.getElementById('e-hardware').textContent.length > 0, { timeout: 15000 })
  let hw = await textOf(w, '#home-hw')
  if (!/enabled on this device/.test(hw) && !process.env.PACT_FAKE_PRF) {
    // A real WebAuthn PRF path that does not work is a failure, not a diagnostic. Testing the wrap
    // logic against an injected PRF is still useful where the platform has no authenticator, so it
    // stays available — behind PACT_FAKE_PRF=1, never as a silent fallback.
    assert.fail(`the PRF path did not work and PACT_FAKE_PRF is not set: ${await textOf(w, '#e-hardware')}`)
  }
  if (!/enabled on this device/.test(hw)) {
    // WebAuthn refused from the extension origin (or the virtual authenticator lacks PRF): test
    // the wrap logic with an injected PRF and say so.
    prf = 'fake PRF injected (' + (await textOf(w, '#e-hardware')) + ')'
    await w.evaluateOnNewDocument(() => {
      const fake = { create: async (o) => ({ rawId: new Uint8Array(16).buffer, getClientExtensionResults: () => ({ prf: { enabled: true, results: { first: new Uint8Array(32).fill(7).buffer } } }) }), get: async (o) => ({ getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(7).buffer } } }) }) }
      Object.defineProperty(navigator, 'credentials', { value: fake, configurable: true })
      window.PublicKeyCredential = function () {}
    })
    await w.reload()
    await waitScreen(w, 's-home')
    await w.click('#b-backup-hw')
    await waitScreen(w, 's-hardware')
    await w.click('#b-hw-device')
    await w.waitForFunction(() => /enabled on this device/.test(document.getElementById('home-hw').textContent), { timeout: 15000 })
    hw = await textOf(w, '#home-hw')
  }
  t.diagnostic('PRF source: ' + prf)
  assert.match(hw, /enabled on this device/)
  await w.click('#b-lock')
  await waitScreen(w, 's-locked')
  assert.equal(await visible(w, '#b-unlock-hw'), true)
  await w.click('#b-unlock-hw')
  await waitScreen(w, 's-home')
  assert.match(await textOf(w, '#status'), /unlocked/)
  // The vault re-sealed under the passphrase still opens: both copies stay in step.
  await w.click('#b-lock')
  await waitScreen(w, 's-locked')
  await w.type('#f-unlock input[name=passphrase]', PASS)
  await w.click('#f-unlock button[type=submit]')
  await waitScreen(w, 's-home')

  // (5b) A session opened by the security key does not know the passphrase. A renewal issued in it
  // must leave the passphrase copy exactly as stored — never re-sealed under the empty string.
  await w.click('#b-lock')
  await waitScreen(w, 's-locked')
  await w.click('#b-unlock-hw')
  await waitScreen(w, 's-home')
  const before = await w.evaluate(() => chrome.storage.local.get(['vault']))
  const renew2 = newCsr('https://bharat.pact.contact/alina/mcp') // the live address since the move in (4); a renewal there asks for no passphrase
  const h5 = await ask(pageA, `window.pact.issueCertificate(${JSON.stringify(renew2.csr)})`)
  const ww = await walletWindow()
  await waitScreen(ww, 's-pick')
  await ww.click('#f-pick button[type=submit]')
  await waitScreen(ww, 's-issue')
  assert.equal(await visible(ww, '#issue-pass-wrap'), false, 'a renewal for a known endpoint asks for no passphrase')
  await ww.click('#b-sign')
  await waitScreen(ww, 's-done')
  const v5 = await h5.value()
  assert.equal(v5.ok, true, JSON.stringify(v5))
  await ww.close()
  const after = await w.evaluate(() => chrome.storage.local.get(['vault', 'vaultStale']))
  assert.equal(after.vaultStale, true, 'the passphrase copy is marked behind')
  assert.deepEqual(after.vault, before.vault, 'the passphrase copy was left exactly as stored')
  assert.throws(() => call('vault_open', { passphrase: '', vault: after.vault }), /vault/, 'nothing opens it with an empty passphrase')
  const stale = call('vault_open', { passphrase: PASS, vault: after.vault })
  const issuedNow = v5.r.chain[0]
  assert.equal(stale.plaintext.ledger.some((l) => l.leaf === issuedNow), false, 'the stored passphrase copy predates the renewal')
  // The stale copy is not opened as if it were current: the passphrase unlock says so.
  await w.click('#b-lock')
  await waitScreen(w, 's-locked')
  await w.type('#f-unlock input[name=passphrase]', PASS)
  await w.click('#f-unlock button[type=submit]')
  await w.waitForFunction(() => document.getElementById('e-unlock').textContent.length > 0, { timeout: 10000 })
  assert.match(await textOf(w, '#e-unlock'), /behind the security key/)
  // The security key opens the current copy, and the passphrase, entered once, refreshes the other.
  await w.click('#b-unlock-hw')
  await waitScreen(w, 's-home')
  assert.equal(await visible(w, '#f-refresh'), true)
  await w.type('#f-refresh input[name=passphrase]', PASS)
  await w.click('#f-refresh button[type=submit]')
  await w.waitForFunction(() => document.getElementById('f-refresh').hidden, { timeout: 10000 })
  const refreshed = await w.evaluate(() => chrome.storage.local.get(['vault', 'vaultStale']))
  assert.equal(refreshed.vaultStale, false)
  const current = call('vault_open', { passphrase: PASS, vault: refreshed.vault })
  assert.equal(current.plaintext.ledger.some((l) => l.leaf === issuedNow), true, 'the passphrase copy now carries the renewal')
  await w.click('#b-lock')
  await waitScreen(w, 's-locked')
  await w.$eval('#f-unlock input[name=passphrase]', (el) => { el.value = '' }) // the refused attempt above left its text in the field
  await w.type('#f-unlock input[name=passphrase]', PASS)
  await w.click('#f-unlock button[type=submit]')
  await waitScreen(w, 's-home')
  await w.close()
})

test('(5b) the window shows who holds a grant, and revoking one makes that page ask again', async () => {
  // Grants lived in a map nobody could see. A person could not answer "which pages can act as
  // me at this moment" — the first question anybody asks of a wallet — and the only way to say
  // no to one was to lock the whole wallet.
  //
  // The grant is taken here rather than assumed: (5) locks, so there is none to inherit, and a
  // test that leaned on one would be asserting the order of the file rather than the behaviour.
  const h = await ask(pageA, 'window.pact.requestIdentity()')
  const granting = await walletWindow()
  await waitScreen(granting, 's-pick')
  await granting.click('#f-pick button[type=submit]')
  await waitScreen(granting, 's-done')
  assert.equal((await h.value()).ok, true)
  await granting.close()

  const w = await browser.newPage()
  await w.goto(`chrome-extension://${extId}/window.html`)
  await waitScreen(w, 's-home')
  await w.click('.tab[data-tab="t-sites"]')
  const origin = new URL(pageA.url()).origin
  await w.waitForFunction((o) => document.getElementById('home-sites').textContent.includes(o), { timeout: 10000 }, origin)
  assert.ok(true, 'the connected pane names the page holding the grant')

  await w.click('#home-sites button.secondary')
  await w.waitForFunction(() => /No page is holding/.test(document.getElementById('home-sites').textContent), { timeout: 10000 })
  const after = await pageA.evaluate(() => window.pact.listCertificates().then(() => 'ok', (e) => e.code))
  assert.equal(after, 'not_granted', 'the revoked page has to ask again')
  await w.close()
})

test('(6) lock clears the unlocked state: grants are gone and a page call is refused', async () => {
  const before = await pageA.evaluate(() => window.pact.listCertificates().then(() => 'ok', (e) => e.code))
  // (5) locked, and (5b) revoked the grant it took afterwards — either way page A arrives here
  // holding nothing, which is what this test needs to be true before it locks again.
  assert.equal(before, 'not_granted', 'page A holds no grant coming into this test')
  const h = await ask(pageA, 'window.pact.requestIdentity()')
  const w = await walletWindow()
  await waitScreen(w, 's-pick')
  await w.click('#f-pick button[type=submit]')
  await waitScreen(w, 's-done')
  assert.equal((await h.value()).ok, true)
  await w.close()
  const certs = (await pageA.evaluate(() => window.pact.listCertificates())).certificates
  assert.equal(certs.length, 5) // A, the move to B, its renewal, the move in (4), and the renewal issued under the security key in (5)
  assert.equal(certs.filter((c) => c.superseded_at).length, 3, 'the two moves superseded every leaf they left behind: A, then B and its renewal')

  const popup = await browser.newPage()
  await popup.goto(`chrome-extension://${extId}/popup.html`)
  await popup.waitForFunction(() => /unlocked/.test(document.getElementById('status').textContent), { timeout: 10000 })
  await popup.click('#b-lock')
  await popup.waitForFunction(() => /locked/.test(document.getElementById('status').textContent) && !/unlocked/.test(document.getElementById('status').textContent), { timeout: 10000 })
  const after = await pageA.evaluate(() => window.pact.listCertificates().then(() => 'ok', (e) => e.code))
  assert.equal(after, 'not_granted')
  await popup.close()

  // The idle alarm takes the same path: unlock, fire the alarm now, watch it lock.
  const w2 = await browser.newPage()
  await w2.goto(`chrome-extension://${extId}/window.html`)
  await waitScreen(w2, 's-locked')
  await w2.type('#f-unlock input[name=passphrase]', PASS)
  await w2.click('#f-unlock button[type=submit]')
  await waitScreen(w2, 's-home')
  const swTarget = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith(`chrome-extension://${extId}`))
  const sw = await swTarget.worker()
  await sw.evaluate(() => chrome.alarms.create('lock', { when: Date.now() }))
  await w2.waitForFunction(() => !document.getElementById('s-locked').hidden || /locked/.test(document.getElementById('status').textContent) && !/unlocked/.test(document.getElementById('status').textContent), { timeout: 15000 })
  await w2.close()
})

test('manifest loads without errors and declares what the README says', async () => {
  const swTarget = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith(`chrome-extension://${extId}`))
  const sw = await swTarget.worker()
  const m = await sw.evaluate(() => chrome.runtime.getManifest())
  assert.equal(m.manifest_version, 3)
  assert.deepEqual(m.permissions.sort(), ['alarms', 'storage'])
  assert.equal(m.host_permissions, undefined)
  const ext = await browser.newPage()
  await ext.goto(`chrome://extensions/?id=${extId}`)
  await sleep(800)
  const errors = await ext.evaluate(() => {
    const texts = []
    const walk = (root) => {
      for (const el of root.querySelectorAll('*')) {
        if (el.shadowRoot) walk(el.shadowRoot)
        if (el.id === 'errors-button' || el.id === 'warnings') texts.push(`${el.id}:${el.hidden ? 'hidden' : 'shown'}:${el.textContent.trim().slice(0, 80)}`)
      }
    }
    walk(document)
    return texts
  })
  assert.ok(!errors.some((e) => e.startsWith('errors-button:shown')), 'chrome://extensions shows an Errors button: ' + errors.join(' | '))
  await ext.close()
})
