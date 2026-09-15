// What the wallet accepts into itself, and what it refuses to throw away.
//
// These run against the service worker's own command port — the same port `window.js` uses —
// because what they are about is the worker's rules, not a screen. Each needs a wallet in a
// particular state (empty, one identity, a security key enrolled), which is why each starts from
// an empty one: ONE browser for the file, wiped between tests. Launching a browser per test looked
// tidier and was the cause of a one-in-five failure — a second `puppeteer.launch` with an unpacked
// extension in a process that already has one sometimes yields a browser whose extension is loaded
// but inert, and the first call then fails in a way that reads like a wallet defect.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import puppeteer from 'puppeteer-core'
import { EXT, chromePath } from './harness.mjs'

const require = createRequire(import.meta.url)
const core = require('../../js/pkg-node/pact_identity_wasm.js')
const call = (name, args) => {
  const out = JSON.parse(core.call(name, JSON.stringify(args)))
  if (out && out.error && !('ok' in out)) throw new Error(`${name}: ${out.error}: ${out.why}`)
  return out
}

const PASS = 'correct horse battery'
const NOW = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')

let solo = null
let extIdOf = null

before(async () => {
  solo = await puppeteer.launch({
    timeout: 60_000,
    executablePath: chromePath(),
    headless: true,
    enableExtensions: [EXT],
    args: ['--no-first-run', '--no-default-browser-check'],
  })
  const sw = await solo.waitForTarget((x) => x.type() === 'service_worker' && x.url().startsWith('chrome-extension://'), { timeout: 20000 })
  extIdOf = new URL(sw.url()).host
})

after(async () => {
  // Politely, then insist: a browser is not always able to exit on its own once a test has been
  // near its service worker, and `close()` then waits for ever. `solo.mjs` learned this.
  if (!solo) return
  await Promise.race([solo.close(), new Promise((r) => setTimeout(r, 5000))]).catch(() => {})
  solo.process()?.kill('SIGKILL')
})

/** A page that can talk to the worker, on a wallet wiped back to empty. */
async function wallet(t) {
  const id = extIdOf
  const w = await solo.newPage()
  t.after(async () => { await w.close().catch(() => {}) })
  await w.goto(`chrome-extension://${id}/window.html`)
  await w.waitForSelector('#main', { timeout: 10000 })
  // An empty wallet, whatever the test before it did: the stored vault and every flag beside it go,
  // and the worker is told to forget the session it may still be holding in memory.
  await w.evaluate(() => new Promise((resolve) => {
    const port = chrome.runtime.connect({ name: 'window' })
    port.onMessage.addListener((m) => { if (m && m.id === 99) { try { port.disconnect() } catch {} ; resolve() } })
    port.postMessage({ id: 99, type: 'lock' })
  }))
  await w.evaluate(() => chrome.storage.local.clear())
  await w.reload()
  await w.waitForSelector('#main', { timeout: 10000 })
  // One port per call. A worker Chrome has stopped wakes on the connect, which is the behaviour the
  // window relies on too, so nothing here depends on the worker having stayed alive between calls.
  await w.evaluate(() => {
    window.__rpc = (msg) => new Promise((resolve, reject) => {
      const port = chrome.runtime.connect({ name: 'window' })
      const timer = setTimeout(() => { try { port.disconnect() } catch {} ; reject(new Error('the worker did not answer')) }, 30_000)
      // Only the reply: the worker also broadcasts `changed`/`locked`/`unlocked` down every open
      // port, and one of those arrives first whenever the command changed something.
      port.onMessage.addListener((m) => {
        if (!m || m.id !== 1) return
        clearTimeout(timer)
        try { port.disconnect() } catch {}
        resolve(m)
      })
      port.postMessage({ id: 1, ...msg })
    })
  })
  return w
}
const rpc = (w, msg) => w.evaluate((m) => window.__rpc(m), msg)
const why = (r) => JSON.stringify(r.error || r.result || r)

test('(7) a restore takes nothing on trust: the certificate, the key and the fingerprint must be the same identity', async (t) => {
  const w = await wallet(t)
  const alina = call('generate_key', { alg: 'ed25519' })
  const mallory = call('generate_key', { alg: 'ed25519' })
  const malloryCert = call('build_root', { cn: 'Mallory', pkcs8: mallory.pkcs8, not_before: NOW }).der

  // A backup filed under Alina's fingerprint, holding Alina's key and MALLORY's certificate. Taken
  // as given, the wallet shows Alina's fingerprint, hands out Mallory's certificate as the root of
  // every chain it signs, and no peer can validate one — with nothing on this side to say why.
  const bad = await rpc(w, { type: 'restore:passkey', passphrase: PASS, roots: { [alina.fingerprint]: { pkcs8: alina.pkcs8, cn: 'Alina Rao', cert: malloryCert, created: NOW } } })
  assert.equal(bad.ok, false, 'a certificate that is not this identity\'s is refused: ' + why(bad))
  assert.equal(bad.error.code, 'bad_request', why(bad))
  assert.match(bad.error.why, new RegExp(mallory.fingerprint.replace(/[+/]/g, '\\$&')), 'it names whose certificate it actually is: ' + why(bad))

  // And nothing of it was kept: the check runs before anything is sealed or stored.
  const stored = await w.evaluate(() => chrome.storage.local.get(['vault', 'hardware', 'passkeyBackup']))
  assert.equal(stored.vault, undefined, 'no vault was written from a refused restore')
  const empty = await rpc(w, { type: 'state' })
  assert.equal(empty.result.hasVault, false)
  assert.equal(empty.result.locked, true, 'a refused restore leaves no session behind: ' + why(empty))

  // The key alone is what a large blob usually holds, and it is enough: the identity is the
  // fingerprint of its public key. What must NOT be guessed is the algorithm — this one is p256,
  // and a wallet that files it as ed25519 is telling the person something untrue about their key.
  const p = call('generate_key', { alg: 'p256' })
  const ok = await rpc(w, { type: 'restore:passkey', passphrase: PASS, roots: { [p.fingerprint]: p.pkcs8 } })
  assert.equal(ok.ok, true, why(ok))
  assert.equal(ok.result.rebuilt, true, 'the certificate was rebuilt from the key')
  assert.equal(ok.result.roots.length, 1)
  assert.equal(ok.result.roots[0].fingerprint, p.fingerprint)
  assert.equal(ok.result.roots[0].alg, 'p256', 'the algorithm is read from the key, not assumed: ' + why(ok))

  // The rebuilt certificate is a root certificate for exactly that identity.
  const vault = (await w.evaluate(() => chrome.storage.local.get('vault'))).vault
  const { plaintext } = call('vault_open', { passphrase: PASS, vault })
  const parsed = call('parse_certificate', { der: plaintext.roots[0].cert })
  assert.equal(parsed.kind, 'root')
  assert.equal(parsed.fingerprint, p.fingerprint)
})

test('(8) a stale flag with no security key behind it does not lock the wallet out of its own vault', async (t) => {
  const w = await wallet(t)
  const made = await rpc(w, { type: 'create', name: 'Alina Rao', alg: 'ed25519', passphrase: PASS })
  assert.equal(made.ok, true, why(made))

  // What a removed security key used to leave behind. "Behind" is a comparison between two copies,
  // and there is only one here, so it cannot be true — but it was stored as a fact rather than
  // worked out, and every export and every read of it believed it for ever.
  await w.evaluate(() => chrome.storage.local.set({ vaultStale: true }))

  const st = await rpc(w, { type: 'state' })
  assert.equal(st.result.vaultStale, false, 'nothing is behind anything when there is one copy: ' + why(st))
  const ex = await rpc(w, { type: 'export' })
  assert.equal(ex.ok, true, 'the vault can still be backed up: ' + why(ex))
  assert.equal(ex.result.vault.format, 'pact-vault/1')

  await rpc(w, { type: 'lock' })
  const un = await rpc(w, { type: 'unlock', passphrase: PASS })
  assert.equal(un.ok, true, 'the passphrase still opens it: ' + why(un))
})

test('(9) the security key\'s copy is the current one: removing the key refuses rather than rolling the wallet back', async (t) => {
  const w = await wallet(t)
  assert.equal((await rpc(w, { type: 'create', name: 'Alina Rao', alg: 'ed25519', passphrase: PASS })).ok, true)

  // `gate` mode, because it needs no authenticator: the key is the wallet's own and the credential
  // only gates it. The staleness this test is about is the same in every mode.
  const KEY = 'k'.repeat(48)
  const on = await rpc(w, { type: 'hardware:enable', mode: 'gate', credentialId: 'cred-1', key: KEY })
  assert.equal(on.ok, true, why(on))

  // A session opened by the key knows no passphrase, so a change made in it can only be sealed into
  // the key's copy. That is what leaves the passphrase copy behind.
  await rpc(w, { type: 'lock' })
  const byKey = await rpc(w, { type: 'unlock:hardware', asserted: true })
  assert.equal(byKey.ok, true, why(byKey))
  const applied = await rpc(w, { type: 'contacts:apply', book: [{ root: 'sha256:' + 'a'.repeat(43), endpoint: 'https://friend.example/mcp', name: 'Friend' }] })
  assert.equal(applied.ok, true, why(applied))
  const stale = await rpc(w, { type: 'state' })
  assert.equal(stale.result.vaultStale, true, 'the passphrase copy is behind the key\'s: ' + why(stale))

  // Removing the key here throws away the only copy that has the contact in it.
  const refused = await rpc(w, { type: 'hardware:disable' })
  assert.equal(refused.ok, false, 'removing the current copy is refused: ' + why(refused))
  assert.equal(refused.error.code, 'stale_vault', why(refused))

  // The way out is the one the home screen offers: the passphrase, once, and both copies are level.
  const refreshed = await rpc(w, { type: 'passphrase:refresh', passphrase: PASS })
  assert.equal(refreshed.ok, true, why(refreshed))
  const off = await rpc(w, { type: 'hardware:disable' })
  assert.equal(off.ok, true, why(off))

  // And what was done in the key's session is still in the wallet the passphrase opens.
  await rpc(w, { type: 'lock' })
  const back = await rpc(w, { type: 'unlock', passphrase: PASS })
  assert.equal(back.ok, true, why(back))
  const book = await rpc(w, { type: 'contacts:get' })
  assert.equal(book.result.contacts.length, 1, 'the contact made under the security key survived its removal: ' + why(book))
  assert.equal((await rpc(w, { type: 'state' })).result.vaultStale, false, 'and nothing is left claiming to be behind')
})

test('(10) a vault file is checked the same way a passkey backup is, and a refused one changes nothing', async (t) => {
  const w = await wallet(t)
  assert.equal((await rpc(w, { type: 'create', name: 'Alina Rao', alg: 'ed25519', passphrase: PASS })).ok, true)
  // A note that a passkey holds a backup of THIS wallet. It is about to stop being true.
  await rpc(w, { type: 'passkey:noted', count: 1 })

  const seal = (roots, passphrase) => call('vault_seal', { passphrase, plaintext: { v: 1, roots, ledger: [], contacts: [] }, kdf: { m_kib: 65536, t: 3, p: 1 } }).vault
  const root = (key, cn) => ({ fingerprint: key.fingerprint, cn, alg: key.alg, pkcs8: key.pkcs8, cert: call('build_root', { cn, pkcs8: key.pkcs8, not_before: NOW }).der, created: NOW })

  // A file the CLI could have written, opened with its own passphrase. It replaces what is here.
  const OTHER = 'a different passphrase entirely'
  const bharat = call('generate_key', { alg: 'p256' })
  const good = seal([root(bharat, 'Bharat Rao')], OTHER)
  const imported = await rpc(w, { type: 'import', vault: good, passphrase: OTHER })
  assert.equal(imported.ok, true, why(imported))
  assert.deepEqual(imported.result.roots.map((r) => r.fingerprint), [bharat.fingerprint])
  assert.equal(imported.result.locked, false, 'the imported vault is the open one')
  assert.equal(imported.result.passkeyBackup, null, 'the note about a passkey holding the OLD identity did not survive: ' + why(imported))

  // And one whose root certificate is somebody else's — the same substitution (7) refuses, arriving
  // through the other door. A vault file is no more trusted than a blob is.
  const mallory = call('generate_key', { alg: 'ed25519' })
  const liar = root(bharat, 'Bharat Rao')
  liar.cert = call('build_root', { cn: 'Mallory', pkcs8: mallory.pkcs8, not_before: NOW }).der
  const refused = await rpc(w, { type: 'import', vault: seal([liar], OTHER), passphrase: OTHER })
  assert.equal(refused.ok, false, 'a vault whose certificate is not its key\'s is refused: ' + why(refused))
  assert.match(refused.error.why, /certificate/, why(refused))

  // Nothing of the refusal stuck: the vault on disk is still the one that was imported.
  const onDisk = (await w.evaluate(() => chrome.storage.local.get('vault'))).vault
  const opened = call('vault_open', { passphrase: OTHER, vault: onDisk })
  assert.deepEqual(opened.plaintext.roots.map((r) => r.fingerprint), [bharat.fingerprint], 'the good import is still what this device holds')
  const st = await rpc(w, { type: 'state' })
  assert.deepEqual(st.result.roots.map((r) => r.fingerprint), [bharat.fingerprint], 'and the open session is untouched: ' + why(st))
})
