// The wallet's service worker: the only place the vault is ever open. It answers pages through
// the bridge, the window and the popup through ports, and holds the unlocked vault in memory —
// never in storage — until it is locked, by hand or by the idle alarm. Every page request that
// needs a decision opens the extension's own window; nothing is signed or granted without a
// click there (SPEC §9).
import { call, CoreError, nowIso } from './core.js'
import { CONFIG } from './config.js'

const REQUEST_KINDS = new Set(['requestIdentity', 'issueCertificate', 'listCertificates', 'syncContacts', 'ceremony'])
const CEREMONY_OPS = new Set(['signup', 'renew', 'move', 'upgrade'])

/** @type {{ passphrase: string, plaintext: any, hwKey: string | null } | null} */
let session = null
/** origin → root fingerprint granted this session */
const grants = new Map()
/** request id → pending page request */
const pending = new Map()
let seq = 0

const fail = (code, why) => Object.assign(new Error(why || code), { code, why: why || code })

// ── storage ───────────────────────────────────────────────────────────────────────────────────
const stored = async (key) => (await chrome.storage.local.get(key))[key]
const store = (obj) => chrome.storage.local.set(obj)

// ── lock and idle ─────────────────────────────────────────────────────────────────────────────
function touch() {
  chrome.alarms.create('lock', { delayInMinutes: CONFIG.AUTO_LOCK_MINUTES })
}
function lock() {
  if (session) {
    session.passphrase = ''
    session.hwKey = null
    session.plaintext = null
  }
  session = null
  grants.clear()
  chrome.alarms.clear('lock')
  broadcast({ type: 'locked' })
}
chrome.alarms.onAlarm.addListener((a) => { if (a.name === 'lock') lock() })

function requireUnlocked() {
  if (!session) throw fail('locked', 'the wallet is locked')
  touch()
  return session.plaintext
}

// Re-seal the vault after any change to its plaintext. Each copy is re-sealed only under a secret
// that is in memory: the passphrase copy when the passphrase is known, the hardware copy when the
// authenticator's secret is. A copy whose secret is not known is left exactly as stored — never
// re-sealed under an empty string — and the next unlock through the other secret asks for this one
// once, so the two copies come back in step.
// Every mutate-seal-store runs in turn. Sealing is Argon2id over 64 MiB, so two flows that overlap
// — a page's issuance in the window and a contacts:apply, or two windows — would otherwise seal
// from the same plaintext and store in the wrong order, and the later write would drop the earlier
// change from storage while memory still showed both.
let persisting = Promise.resolve()
function persist() {
  const run = persisting.then(persistNow, persistNow)
  persisting = run.catch(() => {})
  return run
}

async function persistNow() {
  const s = session
  if (!s) throw fail('locked')
  const updates = {}
  if (s.passphrase) {
    const { vault } = await call('vault_seal', { passphrase: s.passphrase, plaintext: s.plaintext, kdf: CONFIG.KDF })
    updates.vault = vault
    updates.vaultStale = false
  } else {
    updates.vaultStale = true
  }
  const hw = await stored('hardware')
  if (hw) {
    if (s.hwKey) {
      const sealed = await call('vault_seal', { passphrase: s.hwKey, plaintext: s.plaintext, kdf: CONFIG.KDF })
      updates.hardware = { ...hw, vault: sealed.vault, stale: false }
    } else if (!hw.stale) {
      updates.hardware = { ...hw, stale: true }
    }
  }
  await store(updates)
}

// ── identities ────────────────────────────────────────────────────────────────────────────────
const rootsOf = (pt) => (pt.roots || []).map((r) => ({ fingerprint: r.fingerprint, cn: r.cn, created: r.created, alg: r.alg }))
const ledgerOf = (pt, root) => (pt.ledger || []).filter((l) => l.root === root)
// A move supersedes the leaf at the previous address in the wallet's own record: the core reads a
// leaf as live by its dates alone, so the ledger it is handed omits what a move already ended.
const liveLedger = (pt) => ({ ...pt, ledger: (pt.ledger || []).filter((l) => !l.superseded_at) })
const hostOf = (u) => { try { return new URL(u).host } catch { return '' } }

async function createIdentity({ name, alg = 'ed25519', passphrase }) {
  if (!name || !name.trim()) throw fail('bad_request', 'a name is needed')
  if (!passphrase || passphrase.length < 8) throw fail('bad_request', 'the passphrase needs at least eight characters')
  const key = await call('generate_key', { alg })
  const root = await call('build_root', { cn: name.trim(), pkcs8: key.pkcs8, not_before: nowIso() })
  const entry = { fingerprint: root.fingerprint, cn: name.trim(), alg, pkcs8: key.pkcs8, cert: root.der, created: nowIso() }
  key.pkcs8 = ''
  let plaintext
  if (session) {
    plaintext = session.plaintext
    plaintext.roots.push(entry)
  } else {
    plaintext = { v: 1, roots: [entry], ledger: [], contacts: [] }
    session = { passphrase, plaintext, hwKey: null }
  }
  await persist()
  touch()
  broadcast({ type: 'changed' })
  return { fingerprint: root.fingerprint, vault: await stored('vault') }
}

async function unlock(passphrase) {
  const vault = await stored('vault')
  if (!vault) throw fail('no_vault', 'no vault on this device: create an identity or import a backup')
  const hw = await stored('hardware')
  if ((await stored('vaultStale')) && hw && !hw.stale) {
    // The passphrase copy is behind the security key's: opening it would show an older ledger and,
    // on the next change, overwrite the newer copy with it. The key opens the current one.
    throw fail('stale_vault', 'the passphrase copy is behind the security key\'s: unlock with the security key, then enter the passphrase once to refresh it')
  }
  let plaintext
  try { ({ plaintext } = await call('vault_open', { passphrase, vault })) } catch { throw fail('wrong_passphrase', 'the passphrase does not open the vault') }
  session = { passphrase, plaintext, hwKey: null }
  touch()
  broadcast({ type: 'unlocked' })
  return state()
}

async function unlockHardware({ key, asserted }) {
  const hw = await stored('hardware')
  if (!hw) throw fail('no_hardware', 'no hardware-wrapped copy on this device')
  if (hw.stale) throw fail('stale', 'the hardware copy is behind the vault: unlock with the passphrase once, then the copy is refreshed')
  // In `gate` mode the key is the wallet's own and lives in this profile; the credential's part is
  // to have answered. That is a gate on the flow, not a secret at rest, and the wallet says so.
  const hwKey = hw.mode === 'gate' ? (asserted ? hw.key : null) : key
  if (!hwKey) throw fail('wrong_key', 'the authenticator did not answer')
  let plaintext
  try { ({ plaintext } = await call('vault_open', { passphrase: hwKey, vault: hw.vault })) } catch { throw fail('wrong_key', 'this security key does not open the vault') }
  // The passphrase is not known on this path; the vault re-seals under the PRF key only until
  // the passphrase is entered again, so `persist()` keeps both copies in step when it can.
  session = { passphrase: '', plaintext, hwKey }
  touch()
  broadcast({ type: 'unlocked' })
  return state()
}

async function importVault({ vault, passphrase }) {
  if (!vault || vault.format !== 'pact-vault/1') throw fail('bad_request', 'not a pact-vault/1 document')
  let plaintext
  try { ({ plaintext } = await call('vault_open', { passphrase, vault })) } catch { throw fail('wrong_passphrase', 'the passphrase does not open this file') }
  await store({ vault })
  await chrome.storage.local.remove('hardware')
  session = { passphrase, plaintext, hwKey: null }
  touch()
  broadcast({ type: 'changed' })
  return state()
}

async function state() {
  const vault = await stored('vault')
  const hw = await stored('hardware')
  return {
    locked: !session,
    hasVault: !!vault,
    vaultStale: !!(await stored('vaultStale')),
    passphraseKnown: !!(session && session.passphrase),
    hardware: hw ? { enabled: true, mode: hw.mode || 'prf', stale: !!hw.stale } : { enabled: false },
    roots: session ? rootsOf(session.plaintext) : [],
    noticeShown: !!(await stored('noticeShown')),
    passkeyBackup: (await stored('passkeyBackup')) || null,
    drive: !!CONFIG.DRIVE_CLIENT_ID,
    pending: [...pending.values()].map((p) => ({ id: p.id, kind: p.kind, origin: p.origin })),
  }
}

// ── issuance ──────────────────────────────────────────────────────────────────────────────────
async function rootSpkis(pt) {
  const out = []
  for (const r of pt.roots || []) out.push((await call('public_key', { pkcs8: r.pkcs8 })).spki)
  return out
}

/** What the window shows before the person signs: the request, checked against the vault. */
async function prepareIssue(req) {
  const pt = requireUnlocked()
  const root = req.root || grants.get(req.origin) || null
  const check = await call('csr_check', { der: req.args.csr, root_spkis: await rootSpkis(pt) })
  if (!check.ok) throw fail('bad_csr', check.why)
  const out = { endpoint: check.endpoint, cn: check.cn, host_fingerprint: check.fingerprint, alg: check.alg, origin: req.origin, move: !!req.args.move, purpose: req.args.purpose || 'issue', root, needs_grant: !root }
  if (root) {
    const mine = ledgerOf(pt, root)
    const now = Date.now()
    out.new_endpoint = !mine.some((l) => l.endpoint === check.endpoint)
    out.new_host = !mine.some((l) => hostOf(l.endpoint) === hostOf(check.endpoint))
    // The live leaf is the NEWEST one issued, which is how the core decides (§14.3: a later
    // notBefore supersedes every earlier leaf the instant it is seen). Reading any unexpired entry
    // as live refused a renewal at the wallet's own current address whenever an older leaf
    // elsewhere had not expired — which is every vault the CLI wrote, since it records no
    // `superseded_at`.
    const newest = mine.filter((l) => !l.superseded_at).reduce((a, l) => (a && Date.parse(a.not_before) >= Date.parse(l.not_before) ? a : l), null)
    const liveOther = newest && newest.endpoint !== check.endpoint && Date.parse(newest.not_after) > now ? newest : null
    out.live_other = liveOther ? liveOther.endpoint : null
    out.refused = liveOther && !out.move ? `a leaf is live for ${liveOther.endpoint}: a second endpoint is a move, not a second home` : null
    const validDays = req.args.notAfter ? Math.min(398, Math.max(1, Math.ceil((Date.parse(req.args.notAfter) - now) / 86_400_000))) : CONFIG.VALID_DAYS
    out.valid_days = validDays
    out.not_before = nowIso()
    out.not_after = new Date(now + validDays * 86_400_000).toISOString().replace(/\.\d{3}Z$/, 'Z')
  }
  return out
}

async function issue(req, { root, passphrase }) {
  const pt = requireUnlocked()
  const prep = await prepareIssue({ ...req, root })
  if (!root) throw fail('bad_request', 'no identity chosen')
  if (prep.refused) throw fail('one_live_leaf', prep.refused)
  if (prep.new_endpoint) {
    // A new endpoint needs the passphrase again, even in an unlocked session (SPEC §9).
    if (session.passphrase) {
      if (passphrase !== session.passphrase) throw fail('wrong_passphrase', 'the passphrase is needed again for a new endpoint')
    } else {
      const vault = await stored('vault')
      try { await call('vault_open', { passphrase: passphrase || '', vault }) } catch { throw fail('wrong_passphrase', 'the passphrase is needed again for a new endpoint') }
      session.passphrase = passphrase
    }
  }
  const issued = await call('wallet_issue', { vault_plaintext: liveLedger(pt), root_fingerprint: root, csr: req.args.csr, now: nowIso(), valid_days: prep.valid_days, move: prep.move })
  if (prep.move) for (const l of ledgerOf(pt, root)) if (!l.superseded_at && l.endpoint !== issued.endpoint) l.superseded_at = nowIso()
  pt.ledger.push({ ...issued.ledger_entry, origin: req.origin })
  await persist()
  grants.set(req.origin, root)
  const rootCert = pt.roots.find((r) => r.fingerprint === root).cert
  broadcast({ type: 'changed' })
  return { chain: [issued.der, rootCert], root_fingerprint: root, endpoint: issued.endpoint, not_before: issued.not_before, not_after: issued.not_after, warnings: issued.warnings }
}

// ── contacts ──────────────────────────────────────────────────────────────────────────────────
/** A root fingerprint as §2 writes one: `sha256:` and the base64url of a 32-byte hash. */
const isFingerprint = (f) => typeof f === 'string' && /^sha256:[A-Za-z0-9_-]{43}$/.test(f)

/**
 * A contact's `root_cert` is what proves a leaf of theirs off the wire, so it is worth exactly as
 * much as its binding to the fingerprint the book pins. A certificate that hashes to something else
 * is a former host's certificate under a friend's name; it is refused here rather than stored and
 * shown later as a difference.
 */
async function checkContact(c) {
  if (!c || !isFingerprint(c.root)) throw fail('bad_request', 'every contact needs a root fingerprint')
  if (typeof c.endpoint !== 'string' || !c.endpoint) throw fail('bad_request', `${c.root}: every contact needs an endpoint`)
  if (!c.root_cert) return
  let parsed
  try { parsed = await call('parse_certificate', { der: c.root_cert }) }
  catch (e) { throw fail('bad_request', `${c.root}: root_cert does not parse (${e.why || e.message})`) }
  if (parsed.fingerprint !== c.root) throw fail('bad_request', `${c.root}: root_cert is a certificate for ${parsed.fingerprint}, not for the root this contact is pinned by`)
  if (parsed.kind !== 'root') throw fail('bad_request', `${c.root}: root_cert is not a root certificate (${parsed.profile_error || 'not self-signed'})`)
}

function diffContacts(book, theirs) {
  const mine = new Map(book.map((c) => [c.root, c]))
  const proposed = new Map((theirs || []).filter((c) => c && typeof c.root === 'string').map((c) => [c.root, c]))
  const out = []
  for (const [root, c] of proposed) {
    const m = mine.get(root)
    if (!m) out.push({ kind: 'added', root, theirs: c })
    // A root certificate the host holds and the book does not is a difference too: the book
    // keeps it once ticked, and with it a leaf of this contact can be proven off the wire.
    else if (m.endpoint !== c.endpoint || (c.leaf && m.leaf !== c.leaf) || (c.root_cert && m.root_cert !== c.root_cert)) out.push({ kind: 'changed', root, mine: m, theirs: c })
  }
  for (const [root, m] of mine) if (!proposed.has(root)) out.push({ kind: 'removed', root, mine: m })
  return out
}

// ── page requests ─────────────────────────────────────────────────────────────────────────────
async function openWindow(reqId) {
  const url = chrome.runtime.getURL('window.html') + '#req=' + encodeURIComponent(reqId)
  const w = await chrome.windows.create({ url, type: 'popup', focused: true, width: 480, height: 680 })
  return w.id
}

chrome.windows.onRemoved.addListener((windowId) => {
  for (const p of pending.values()) if (p.windowId === windowId) settle(p.id, null, fail('cancelled', 'the wallet window was closed'))
})

function settle(id, result, error) {
  const p = pending.get(id)
  if (!p) return
  pending.delete(id)
  if (p.timer) clearTimeout(p.timer)
  if (error) p.reject(error)
  else p.resolve(result)
}

async function handlePage(op, args, origin) {
  if (!REQUEST_KINDS.has(op)) throw fail('bad_request', `no such call: ${op}`)
  touch()
  if (op === 'listCertificates') {
    const root = grants.get(origin)
    if (!root) throw fail('not_granted', 'call requestIdentity first')
    const pt = requireUnlocked()
    return { root_fingerprint: root, certificates: ledgerOf(pt, root).map((l) => ({ leaf: l.leaf, endpoint: l.endpoint, not_before: l.not_before, not_after: l.not_after, issued_at: l.issued_at, superseded_at: l.superseded_at || null })) }
  }
  if (op === 'issueCertificate' && (typeof args?.csr !== 'string' || !args.csr)) throw fail('bad_request', 'issueCertificate needs a CSR (base64url DER)')
  if (op === 'ceremony') {
    if (!CEREMONY_OPS.has(args?.op)) throw fail('bad_request', 'unknown ceremony op')
    if (typeof args.csr !== 'string' || !args.csr) throw fail('bad_request', 'the ceremony needs a CSR')
  }
  if (op === 'syncContacts' && !Array.isArray(args?.contacts)) throw fail('bad_request', 'syncContacts needs a list')
  const id = `r${++seq}-${Math.random().toString(36).slice(2, 8)}`
  const p = { id, kind: op, origin, args: args || {}, windowId: null, created: Date.now(), opening: true }
  const done = new Promise((resolve, reject) => { p.resolve = resolve; p.reject = reject })
  pending.set(id, p)
  // A page that is never answered is worse than one that is refused: a request left in the map
  // keeps a promise alive in the page for ever. It ends when its window closes, when the person
  // decides, or when this deadline passes.
  p.timer = setTimeout(() => settle(id, null, fail('timeout', 'the wallet was not answered in time')), CONFIG.REQUEST_TIMEOUT_MINUTES * 60_000)
  try {
    p.windowId = await openWindow(id)
    p.opening = false
    // A window closed while it was still opening is not in `onRemoved`'s reach: check now.
    const gone = !(await chrome.windows.get(p.windowId).catch(() => null))
    if (gone) settle(id, null, fail('cancelled', 'the wallet window was closed'))
  } catch (e) {
    p.opening = false
    settle(id, null, fail('no_window', String(e)))
  }
  return done
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== 'page') return false
  const origin = sender.origin || (sender.url ? new URL(sender.url).origin : 'null')
  handlePage(msg.op, msg.args, origin)
    .then((result) => sendResponse({ ok: true, result }))
    .catch((e) => sendResponse({ ok: false, error: { code: e.code || 'internal', why: e.why || e.message } }))
  return true
})

// ── window and popup ports ────────────────────────────────────────────────────────────────────
const ports = new Set()
function broadcast(msg) { for (const p of ports) { try { p.postMessage(msg) } catch { /* gone */ } } }

async function requestFor(reqId) {
  const p = pending.get(reqId)
  if (!p) throw fail('no_request', 'that request is gone')
  const base = { id: p.id, kind: p.kind, origin: p.origin }
  if (p.kind === 'requestIdentity') return { ...base, granted: grants.get(p.origin) || null }
  if (p.kind === 'issueCertificate') return { ...base, ...(session ? await prepareIssue(p) : { locked: true }) }
  if (p.kind === 'ceremony') {
    const a = p.args
    const req = { ...p, args: { csr: a.csr, move: a.op === 'move', purpose: a.op } }
    return { ...base, op: a.op, display_name: a.display_name || '', endpoint_hint: a.endpoint || '', new_host_hint: !!a.new_host, ...(session ? await prepareIssue(req) : { locked: true }) }
  }
  if (p.kind === 'syncContacts') {
    const pt = requireUnlocked()
    return { ...base, differences: diffContacts(pt.contacts || [], p.args.contacts), count: (pt.contacts || []).length }
  }
  return base
}

async function command(msg) {
  switch (msg.type) {
    // A window that is open holds the worker awake so the unlocked vault survives while a person
    // is filling a form. It deliberately does NOT touch(): the idle lock is about the person
    // being away, and a ticking keepalive must not stand in for them being here.
    case 'keepalive': return { awake: true }
    case 'state': return state()
    case 'request': return requestFor(msg.reqId)
    case 'unlock': return unlock(msg.passphrase)
    case 'unlock:hardware': return unlockHardware({ key: msg.key, asserted: !!msg.asserted })
    case 'lock': lock(); return state()
    case 'create': return createIdentity(msg)
    case 'import': return importVault(msg)
    case 'export': {
      requireUnlocked()
      if (await stored('vaultStale')) throw fail('stale_vault', 'the passphrase copy is behind: enter the passphrase once to refresh it before exporting')
      return { vault: await stored('vault') }
    }
    case 'passphrase:refresh': {
      // After a security-key unlock: prove the passphrase opens the stored copy, then re-seal both
      // copies from the plaintext in memory so the passphrase copy is current again.
      const pt = requireUnlocked()
      const vault = await stored('vault')
      try { await call('vault_open', { passphrase: msg.passphrase || '', vault }) } catch { throw fail('wrong_passphrase', 'the passphrase does not open the vault') }
      session.passphrase = msg.passphrase
      session.plaintext = pt
      await persist()
      broadcast({ type: 'changed' })
      return state()
    }
    case 'notice:shown': await store({ noticeShown: true }); return { ok: true }
    case 'grant': {
      const p = pending.get(msg.reqId)
      if (!p) throw fail('no_request')
      requireUnlocked()
      if (!session.plaintext.roots.some((r) => r.fingerprint === msg.root)) throw fail('bad_request', 'no such identity')
      grants.set(p.origin, msg.root)
      if (p.kind === 'requestIdentity') {
        const r = session.plaintext.roots.find((x) => x.fingerprint === msg.root)
        settle(p.id, { root_fingerprint: r.fingerprint, cn: r.cn })
      }
      return { ok: true }
    }
    case 'deny': settle(msg.reqId, null, fail(msg.code || 'denied', msg.why || 'the person declined')); return { ok: true }
    case 'issue': {
      const p = pending.get(msg.reqId)
      if (!p) throw fail('no_request')
      const req = p.kind === 'ceremony' ? { ...p, args: { csr: p.args.csr, move: p.args.op === 'move', purpose: p.args.op } } : p
      try {
        const result = await issue(req, { root: msg.root, passphrase: msg.passphrase })
        settle(p.id, result)
        return result
      } catch (e) {
        if (e.code === 'one_live_leaf' || e.code === 'bad_csr') settle(p.id, null, e)
        throw e
      }
    }
    case 'ledger': { const pt = requireUnlocked(); return { entries: ledgerOf(pt, msg.root) } }
    case 'contacts:get': { const pt = requireUnlocked(); return { contacts: pt.contacts || [] } }
    case 'contacts:apply': {
      const pt = requireUnlocked()
      const p = pending.get(msg.reqId)
      if (!Array.isArray(msg.book)) throw fail('bad_request')
      for (const c of msg.book) await checkContact(c)
      pt.contacts = msg.book.map((c) => ({ root: c.root, endpoint: c.endpoint, name: c.name || '', leaf: c.leaf || undefined, root_cert: c.root_cert || undefined, added: c.added || nowIso() }))
      await persist()
      if (p) settle(p.id, { contacts: pt.contacts, book: pt.contacts }) // `book`: the name the portal's return-with-archive screen reads
      return { contacts: pt.contacts }
    }
    // Only that one was made, and when: the passkey holds the backup, not this record.
    case 'passkey:noted': { await store({ passkeyBackup: { at: nowIso(), count: msg.count || 1 } }); return { ok: true } }
    case 'hardware:get': { const hw = await stored('hardware'); return hw ? { mode: hw.mode || 'prf', credentialId: hw.credentialId, salt: hw.salt, stale: !!hw.stale } : null }
    // The root keys, handed to the wallet's own window for one purpose: writing them into an
    // authenticator that can hold them. No page can reach this — the bridge does not forward it —
    // but it is the one moment a root leaves the worker, and it is worth naming as such.
    case 'hardware:secrets': {
      const pt = requireUnlocked()
      // Everything a restore needs to rebuild the identity: the key, the name the certificate
      // carries, the certificate itself when the blob will take it, and when it was made.
      return { roots: Object.fromEntries((pt.roots || []).map((r) => [r.fingerprint, { pkcs8: r.pkcs8, cn: r.cn, cert: r.cert, created: r.created, alg: r.alg }])) }
    }
    // A restore on a machine that has never seen this wallet: the passkey held the root, the rest
    // is rebuilt. The ledger and the contact book were not in it and are not invented here — the
    // wallet says so rather than starting with an empty history that looks like a real one.
    case 'restore:passkey': {
      if (await stored('vault')) throw fail('bad_request', 'this device already holds a vault; a restore would replace it')
      const passphrase = msg.passphrase
      if (!passphrase || passphrase.length < 8) throw fail('bad_request', 'the passphrase needs at least eight characters')
      const entries = Object.entries(msg.roots || {})
      if (!entries.length) throw fail('bad_request', 'that backup holds no identity')
      const roots = []
      for (const [fingerprint, r] of entries) {
        const pkcs8 = typeof r === 'string' ? r : r.pkcs8
        if (!pkcs8) throw fail('bad_request', 'that backup holds no key')
        const cn = (typeof r === 'object' && r.cn) || 'Restored identity'
        // The certificate, rebuilt from the key when the blob could not carry it. The identity is
        // the fingerprint of the public key (SPEC §2), so the rebuilt one is the same identity and
        // every contact's pin still matches; only the bytes differ.
        let cert = typeof r === 'object' ? r.cert : null
        let rebuilt = false
        if (!cert) {
          const made = await call('build_root', { cn, pkcs8, not_before: (typeof r === 'object' && r.created) || nowIso() })
          if (made.fingerprint !== fingerprint) throw fail('bad_request', 'the key in that backup is not the identity it names')
          cert = made.der
          rebuilt = true
        }
        roots.push({ fingerprint, cn, alg: (typeof r === 'object' && r.alg) || 'ed25519', pkcs8, cert, created: (typeof r === 'object' && r.created) || nowIso(), restored: true, certRebuilt: rebuilt })
      }
      const plaintext = { v: 1, roots, ledger: [], contacts: [] }
      const { vault } = await call('vault_seal', { passphrase, plaintext, kdf: CONFIG.KDF })
      await store({ vault, vaultStale: false, noticeShown: true })
      session = { passphrase, plaintext, hwKey: null }
      touch()
      broadcast({ type: 'changed' })
      return { roots: rootsOf(plaintext), rebuilt: roots.some((r) => r.certRebuilt) }
    }
    case 'hardware:enable': {
      const pt = requireUnlocked()
      const mode = msg.mode || 'prf'
      if (!['prf', 'root-on-key', 'gate'].includes(mode)) throw fail('bad_request', `unknown hardware mode ${mode}`)
      if (typeof msg.key !== 'string' || msg.key.length < 32) throw fail('bad_request', 'the authenticator gave no secret')
      const sealed = await call('vault_seal', { passphrase: msg.key, plaintext: pt, kdf: CONFIG.KDF })
      const record = { mode, credentialId: msg.credentialId, salt: msg.salt, vault: sealed.vault, stale: false }
      // `gate` alone keeps its key here: nothing else can hold it, which is the whole of what that
      // mode is and is not.
      if (mode === 'gate') record.key = msg.key
      await store({ hardware: record })
      session.hwKey = msg.key
      return { ok: true }
    }
    case 'hardware:disable': await chrome.storage.local.remove('hardware'); if (session) session.hwKey = null; return { ok: true }
    default: throw fail('bad_request', `unknown command ${msg.type}`)
  }
}

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'window' && port.name !== 'popup') return
  ports.add(port)
  port.onDisconnect.addListener(() => ports.delete(port))
  port.onMessage.addListener(async (msg) => {
    try {
      const result = await command(msg)
      port.postMessage({ id: msg.id, ok: true, result })
    } catch (e) {
      const code = e instanceof CoreError ? e.code : e.code || 'internal'
      port.postMessage({ id: msg.id, ok: false, error: { code, why: e.why || e.message } })
    }
  })
})
