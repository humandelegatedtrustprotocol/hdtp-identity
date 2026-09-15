// The three hardware modes, in their own file because each needs its own browser: a virtual
// authenticator is a property of the whole environment, and Chrome allows one "internal" one per
// browser. Node's test runner gives each FILE its own process, which is what keeps these launches
// from contending with the shared browser the other suites hold open.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import puppeteer from 'puppeteer-core'
import { EXT, chromePath, visible, textOf, waitScreen, sleep } from './harness.mjs'

const require = createRequire(import.meta.url)
const core = require('../../js/pkg-node/pact_identity_wasm.js')
const call = (name, args) => {
  const out = JSON.parse(core.call(name, JSON.stringify(args)))
  if (out && out.error && !('ok' in out)) throw new Error(`${name}: ${out.error}: ${out.why}`)
  return out
}

const PASS = 'correct horse battery'

// Unlocking has two mechanisms — PRF, and a gate for a credential that cannot derive one — and
// backing up has one, which is where a large blob now belongs: the passkey is a backup, not the
// live key store. Each test takes its own browser, because a virtual authenticator belongs to one.
async function hwPage(t, options) {
  // Its own browser. A virtual authenticator is a property of the whole environment, and two of
  // them in one browser made these tests pass or fail by which ran first. This configuration is the
  // one observed to pass all three together; see the README's note on why the suite is fragile here.
  const solo = await puppeteer.launch({
    executablePath: chromePath(),
    headless: true,
    enableExtensions: [EXT],
    args: ['--no-first-run', '--no-default-browser-check'],
  })
  t.after(async () => { await solo.close().catch(() => {}) })
  const sw = await solo.waitForTarget((x) => x.type() === 'service_worker' && x.url().startsWith('chrome-extension://'), { timeout: 20000 })
  const id = new URL(sw.url()).host
  const w = await solo.newPage()
  const cdp = await w.createCDPSession()
  await cdp.send('WebAuthn.enable', { enableUI: false })
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, ...options },
  })
  await w.goto(`chrome-extension://${id}/window.html`)
  // Which screen the wallet opened on, by the flag the wallet itself sets. `visible()` also asks for
  // `offsetParent`, which is null until the page has been laid out — so on a loaded machine this
  // read "neither create nor locked" a frame after the create form appeared, took neither branch,
  // and then waited ninety seconds for a home screen nothing was ever going to reach. Two runs of
  // the full suite were lost to it; the page it timed out on was showing `s-create` the whole time.
  const on = (sel) => w.evaluate((x) => { const el = document.getElementById(x); return !!el && !el.hidden }, sel)
  await w.waitForFunction(() => ['s-create', 's-locked', 's-home'].some((x) => { const el = document.getElementById(x); return el && !el.hidden }), { timeout: 30000 })
  if (await on('s-create')) {
    await w.type('#f-create input[name=name]', 'Hardware Holder')
    await w.type('#f-create input[name=passphrase]', PASS)
    await w.type('#f-create input[name=again]', PASS)
    await w.click('#f-create input[name=understood]')
    await w.click('#f-create button[type=submit]')
    await waitScreen(w, 's-hardware')
    await w.click('#b-hw-skip')
  }
  if (await on('s-locked')) {
    await w.type('#f-unlock input[name=passphrase]', PASS)
    await w.click('#f-unlock button[type=submit]')
  }
  // Setup, not an assertion: this waits on an Argon2id seal at 64 MiB inside wasm, and on a loaded
  // machine that is where the whole suite's time goes.
  try {
    await w.waitForFunction(() => { const h = document.getElementById('s-home'); return h && !h.hidden }, { timeout: 90000 })
  } catch (e) {
    // A wait that says only "timed out" is where an afternoon goes. Name the screen it stopped on
    // and whatever that screen was trying to say.
    const seen = await w.evaluate(() => ({
      screen: ([...document.querySelectorAll('.screen')].find((x) => !x.hidden) || {}).id || 'none',
      status: (document.getElementById('status') || {}).textContent || '',
      errors: [...document.querySelectorAll('.err, [id^=e-]')].map((x) => x.textContent.trim()).filter(Boolean),
      disconnected: !(document.getElementById('disconnected') || { hidden: true }).hidden,
    })).catch(() => null)
    throw new Error(`the wallet never reached its home screen: ${JSON.stringify(seen)} — ${e.message}`)
  }
  return w
}

test('(3) with PACT_FAKE_PRF unset, an authenticator without PRF is a reported failure, never a quiet pass', async (t) => {
  assert.equal(process.env.PACT_FAKE_PRF, undefined, 'this test is about the unset case')
  // The same authenticator run.mjs uses for the real path, minus PRF — in its own browser, so this
  // runs on its own as readily as it runs after the others.
  const w = await hwPage(t, {})
  await w.click('#b-backup-hw')
  // From home the wallet goes to the screen with the two doors rather than registering on the spot.
  // An unpinned registration is one a password manager can take from a security key, which is the
  // whole reason that screen has two buttons and home no longer has one.
  await waitScreen(w, 's-hardware')
  assert.equal(await visible(w, '#b-hw-enable'), true, 'the security-key door')
  assert.equal(await visible(w, '#b-hw-device'), true, 'and this device\'s own')
  await w.click('#b-hw-enable') // this virtual authenticator is `usb`: the security-key door
  // Nothing is enabled: the wallet stays on the enrolment screen and says why, where the gate offer
  // of (5) waits for a second, explicit click.
  await waitScreen(w, 's-hardware')
  await w.waitForFunction(() => document.getElementById('e-hardware').textContent.length > 0, { timeout: 20000 })
  const hw = await textOf(w, '#home-hw')
  const err = await textOf(w, '#e-hardware')
  t.diagnostic(`without PRF: home-hw=${JSON.stringify(hw)} e-home=${JSON.stringify(err)}`)
  assert.ok(!/enabled on this device/.test(hw), 'an authenticator without PRF must not report the key as enabled')
  assert.ok(err.length > 0, 'the window says why it could not: ' + JSON.stringify(err))
  // This is exactly the state in which run.mjs fails rather than falling back, since the fallback
  // now lives behind PACT_FAKE_PRF. The vault stays as it was: no half-wrapped copy.
  const stored = await w.evaluate(() => chrome.storage.local.get(['hardware', 'vaultStale']))
  assert.equal(stored.hardware, undefined, 'no hardware record was written')
  assert.ok(!stored.vaultStale, 'the passphrase copy is not marked behind by a failure')
})

test('(5) gate: a passkey that can hold nothing is offered as a gate, only after the cost is stated', async (t) => {
  const w = await hwPage(t, {}) // neither PRF nor largeBlob: where 1Password lands
  await w.click('#b-backup-hw')
  // From home the wallet goes to the screen with the two doors rather than registering on the spot.
  // An unpinned registration is one a password manager can take from a security key, which is the
  // whole reason that screen has two buttons and home no longer has one.
  await waitScreen(w, 's-hardware')
  await w.click('#b-hw-enable')
  // Nothing is enabled behind the person's back: the offer appears on the same screen.
  await waitScreen(w, 's-hardware')
  await w.waitForFunction(() => { const g = document.getElementById('hw-gate'); return g && !g.hidden }, { timeout: 20000 })
  // The markup wraps, so the assertions read the collapsed text rather than the source's line breaks.
  const said = (await textOf(w, '#hw-gate')).replace(/\s+/g, ' ').trim()
  t.diagnostic(`gate offer: ${JSON.stringify(said.slice(0, 140))}`)
  assert.match(said, /cannot hold a secret/, 'it says what the passkey cannot do')
  assert.match(said, /Anyone with this profile could read that key without the passkey/, 'and what that costs')
  assert.match(said, /passphrase/, 'and what still protects the vault')

  await w.click('#b-hw-gate')
  await waitScreen(w, 's-home')
  await w.waitForFunction(() => /gates this device/.test(document.getElementById('home-hw').textContent), { timeout: 20000 })
  const held = await w.evaluate(async () => {
    const { hardware } = await chrome.storage.local.get('hardware')
    return { mode: hardware.mode, hasKeyInProfile: typeof hardware.key === 'string' }
  })
  assert.equal(held.mode, 'gate')
  assert.equal(held.hasKeyInProfile, true, 'the key is in this profile, which is exactly what the panel said')

  await w.click('#b-lock')
  await waitScreen(w, 's-locked')
  await w.click('#b-unlock-hw')
  await waitScreen(w, 's-home')
  assert.match(await textOf(w, '#status'), /unlocked/)
})

test('(6) a passkey backup restores the identity on a machine that has never seen it', async (t) => {
  // The shape the owner settled on: the passkey is a BACKUP, not the live key store. One machine
  // writes the root to it; another, with nothing of its own, reads it back and becomes the working
  // wallet — the fingerprint contacts pin is the same, because it is the fingerprint of the key.
  const solo = await puppeteer.launch({
    executablePath: chromePath(), headless: true, enableExtensions: [EXT],
    args: ['--no-first-run', '--no-default-browser-check'],
  })
  t.after(async () => { await solo.close().catch(() => {}) })
  const sw = await solo.waitForTarget((x) => x.type() === 'service_worker' && x.url().startsWith('chrome-extension://'), { timeout: 20000 })
  const id = new URL(sw.url()).host
  const w = await solo.newPage()
  const cdp = await w.createCDPSession()
  await cdp.send('WebAuthn.enable', { enableUI: false })
  // A blob-capable passkey, the kind a person keeps a backup in.
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasLargeBlob: true },
  })
  await w.goto(`chrome-extension://${id}/window.html`)
  await waitScreen(w, 's-create')
  await w.type('#f-create input[name=name]', 'Alina Rao')
  await w.type('#f-create input[name=passphrase]', PASS)
  await w.type('#f-create input[name=again]', PASS)
  await w.click('#f-create input[name=understood]')
  await w.click('#f-create button[type=submit]')
  await waitScreen(w, 's-hardware')
  await w.click('#b-hw-skip')
  await waitScreen(w, 's-home')
  const made = await w.evaluate(() => new Promise((r) => {
    const port = chrome.runtime.connect({ name: 'window' })
    port.onMessage.addListener((m) => { if (m.id === 1) r(m.result.roots[0].fingerprint) })
    port.postMessage({ id: 1, type: 'state' })
  }))

  // 1. The backup, beside the file and Drive kinds.
  await w.click('#b-backup-passkey')
  await w.waitForFunction(() => /written/.test(document.getElementById('home-passkey').textContent) || document.getElementById('e-home').textContent.length > 0, { timeout: 30000 })
  assert.equal(await textOf(w, '#e-home'), '', 'the backup was written')
  assert.match(await textOf(w, '#home-passkey'), /written/)
  // And the screen says what it is and is not.
  const backupSays = (await w.evaluate(() => document.getElementById('s-home').textContent)).replace(/\s+/g, ' ')
  assert.match(backupSays, /whoever can use that passkey can become you/, 'what the copy exposes')
  assert.match(backupSays, /does not hold the ledger or your contacts/, 'what it leaves behind')
  assert.match(backupSays, /If your passkey syncs, this copy syncs with it/, 'and no promise about syncing')

  // 2. A machine that has never seen this wallet. Same browser, so the same authenticator answers;
  //    the profile's own storage is cleared, which is what "never seen it" means to the extension.
  // Locked first: the worker holds the unlocked vault in memory, and clearing storage under it
  // would leave a session with nothing behind it — which is not what a new machine looks like.
  await w.click('#b-lock')
  await waitScreen(w, 's-locked')
  await w.evaluate(() => chrome.storage.local.clear())
  await w.reload()
  await waitScreen(w, 's-create')
  await w.click('#l-restore-passkey-2')
  await waitScreen(w, 's-restore')
  const restoreSays = (await textOf(w, '#s-restore')).replace(/\s+/g, ' ')
  assert.match(restoreSays, /ledger and the contact book were not in the backup/, 'the restore screen says what is missing')
  assert.match(restoreSays, /start date later than any it later sees/, 'and what that means for the next leaf')
  await w.type('#f-restore input[name=passphrase]', PASS)
  await w.type('#f-restore input[name=again]', PASS)
  await w.click('#f-restore button[type=submit]')
  await waitScreen(w, 's-home')

  const back = await w.evaluate(() => new Promise((r) => {
    const port = chrome.runtime.connect({ name: 'window' })
    port.onMessage.addListener((m) => { if (m.id === 1) r(m.result.roots) })
    port.postMessage({ id: 1, type: 'state' })
  }))
  assert.equal(back.length, 1, 'one identity came back')
  assert.equal(back[0].fingerprint, made, 'and it is the same identity: the fingerprint is of the key')
  t.diagnostic(`restored ${back[0].cn} ${back[0].fingerprint.slice(0, 22)}…`)

  // 3. The restored wallet can act as the identity: a leaf issued from the key it now holds
  //    validates to the same root every contact pinned. The key comes back through the same door
  //    the backup used, which is the only way to reach it without driving a page's request.
  const secrets = await w.evaluate(() => new Promise((r) => {
    const port = chrome.runtime.connect({ name: 'window' })
    port.onMessage.addListener((m) => { if (m.id === 1) r(m.ok ? m.result : null) })
    port.postMessage({ id: 1, type: 'hardware:secrets' })
  }))
  assert.ok(secrets && secrets.roots[made], 'the restored wallet holds the root key')
  const host = call('generate_key', { alg: 'ed25519' })
  const { der: csr } = call('csr_new', { cn: 'Alina Rao', host_pkcs8: host.pkcs8, endpoint: 'https://alina.pact.contact/alina/mcp' })
  const leaf = call('issue_from_csr', {
    csr, root_cn: secrets.roots[made].cn, root_pkcs8: secrets.roots[made].pkcs8,
    now: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  })
  const v = call('validate_chain', {
    chain: [leaf.der, secrets.roots[made].cert],
    now: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    expected_root: made,
    expected_endpoint: 'https://alina.pact.contact/alina/mcp',
  })
  assert.equal(v.ok, true, `a leaf from the restored wallet validates to the pinned root: ${JSON.stringify(v)}`)
  t.diagnostic('a leaf issued from the restored key validates to ' + made.slice(0, 22) + '…')

  // The other consequence — that it knows of no certificates it has issued and of nobody it knows
  // — is what the restore screen says above, asserted there; the wallet's own ledger view is the
  // place to see it, and driving that needs a page's request this test does not make.

  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId }).catch(() => {})
})
