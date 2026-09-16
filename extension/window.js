// The wallet's own window: every grant and every signature happens here, after a click, in a
// window no page can draw over. It talks to the service worker over a port and renders one
// screen at a time from the state and the request it was opened for.
import * as hardware from './hardware.js'
import * as drive from './drive.js'

// MV3 stops the service worker about thirty seconds after it goes quiet, which disconnects every
// port. A window outlives that easily — a person typing a name and a passphrase twice is already
// past it — so a port captured once and kept is a port that is dead by the time they click, and
// `postMessage` on it throws "Attempting to use a disconnected port object". The port is therefore
// made on demand and remade when it has gone: connecting is also what wakes the worker.
let port = null
const waiting = new Map()
let n = 0
function livePort() {
  if (port) return port
  port = chrome.runtime.connect({ name: 'window' })
  port.onMessage.addListener(onMessage)
  port.onDisconnect.addListener(onDisconnect)
  return port
}
function onMessage(m) {
  if (m && typeof m.id === 'number' && waiting.has(m.id)) {
    const { resolve, reject } = waiting.get(m.id)
    waiting.delete(m.id)
    if (m.ok) resolve(m.result)
    else reject(Object.assign(new Error(m.error.why || m.error.code), { code: m.error.code }))
    return
  }
  if (m && (m.type === 'locked' || m.type === 'changed' || m.type === 'unlocked')) refreshStatus()
}
// A call already in flight when the worker stops is lost — it may or may not have been carried out,
// so it is refused rather than retried. The next call reconnects, which is also what wakes the
// worker again.
//
// Whether to SAY so depends on what died with it. A page's request and an unlocked vault both live
// in the worker's memory: if this window was opened for a request, or the wallet was unlocked, the
// person is looking at a screen that is no longer backed by anything and must be told. A window
// making an identity with nothing pending has lost nothing — the form is here, the work has not
// started — and an error there would be a lie about the state of their wallet.
let unlockedHere = false
function onDisconnect() {
  port = null
  const gone = Object.assign(new Error('the wallet locked itself while this window was open; check what it holds and try again'), { code: 'disconnected' })
  const lost = waiting.size
  for (const { reject } of waiting.values()) reject(gone)
  waiting.clear()
  const note = document.getElementById('disconnected')
  if (note && (lost > 0 || reqId || unlockedHere)) note.hidden = false
}

function rpc(type, fields = {}) {
  const id = ++n
  return new Promise((resolve, reject) => {
    waiting.set(id, { resolve, reject })
    // A send that throws never reached the worker, so sending it again on a fresh port cannot
    // repeat anything. A reply lost after the send is the case above, which is refused, not retried.
    try {
      livePort().postMessage({ id, type, ...fields })
    } catch {
      port = null
      try {
        livePort().postMessage({ id, type, ...fields })
      } catch (e) {
        waiting.delete(id)
        reject(e)
      }
    }
  })
}

// While this window is open the worker stays awake, so an unlocked vault is still there when the
// person finally clicks. The idle lock is untouched by this: it measures the person, not the port.
setInterval(() => { rpc('keepalive').catch(() => {}) }, 20_000)

// What each mode actually gives, in the words the home screen shows. "enabled" alone would hide the
// difference between a secret the authenticator holds and a key this profile holds for it.
const HW_MODE = { // invariant: constant
  prf: 'the key derives the secret',
  'root-on-key': 'your identity is on the key',
  gate: 'the key gates this device\'s copy',
}

const $ = (id) => document.getElementById(id)
const screens = [...document.querySelectorAll('.screen')]
function show(id) {
  for (const s of screens) s.hidden = s.id !== id
  const first = document.querySelector(`#${id} input:not([type=hidden]):not([type=checkbox]):not([type=file]), #${id} button.primary`)
  if (first) first.focus()
}
const text = (id, v) => { $(id).textContent = v }
const err = (id, e) => { $(id).textContent = e ? (e.why || e.message || String(e)) : '' }
const short = (fp) => fp.length > 24 ? fp.slice(0, 15) + '…' + fp.slice(-6) : fp
const when = (iso) => iso ? iso.replace('T', ' ').replace(/Z$/, ' UTC') : ''

const reqId = new URLSearchParams(location.hash.slice(1)).get('req')
let state = null
let request = null

async function refreshStatus() {
  // Remembered so a disconnect knows whether an unlocked session died with the worker. It tracks
  // the wallet rather than latching: after a deliberate Lock, or the idle lock, nothing unlocked is
  // left to lose, and a worker evicted afterwards must not tell the person it locked itself.
  state = await rpc('state')
  unlockedHere = !state.locked
  text('status', state.locked ? 'locked' : `${state.roots.length} identit${state.roots.length === 1 ? 'y' : 'ies'} · unlocked`)
  $('status').className = 'pill ' + (state.locked ? 'locked' : 'open')
  // The countdown the wallet never showed. It locks after fifteen idle minutes and said nothing,
  // so a person could not tell whether they had a moment or a quarter of an hour.
  const left = state.locksAt ? Math.round((state.locksAt - Date.now()) / 60000) : null
  $('locks-in').hidden = left === null || left < 0
  if (left !== null && left >= 0) $('locks-in').textContent = left <= 1 ? 'locks in under a minute' : `locks in ${left} min`
}

function download(name, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2) + '\n'], { type: 'application/json' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = name
  document.body.appendChild(a)
  a.click()
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove() }, 1000)
}

// ── routing ───────────────────────────────────────────────────────────────────────────────────
async function start() {
  await refreshStatus()
  if (reqId) {
    try { request = await rpc('request', { reqId }) } catch (e) { return done('Request gone', e.message) }
  }
  route()
}

function route() {
  if (state.locked) {
    if (!state.hasVault) {
      if (request && request.kind === 'ceremony') $('f-create').elements.name.value = request.display_name || ''
      return show('s-create')
    }
    return lockedScreen()
  }
  if (!request) return home()
  return handleRequest()
}

function lockedScreen() {
  $('b-unlock-hw').hidden = !(state.hardware.enabled && !state.hardware.stale && hardware.hasWebAuthn())
  return show('s-locked')
}

async function handleRequest() {
  try { request = await rpc('request', { reqId }) } catch (e) { return done('Request gone', e.message) }
  // The wallet can lock between this window being routed and the request being read. The worker
  // says so on every kind of request now, and this is what that answer is for: the unlock screen,
  // which comes back through `route` the moment the person is past it. Without this the shape was
  // returned and ignored, and the screen drew itself from fields that were not there.
  if (request.locked) { await refreshStatus(); return lockedScreen() }
  switch (request.kind) {
    case 'requestIdentity': return pick()
    case 'issueCertificate':
    case 'ceremony':
      if (request.needs_grant) return pick(true)
      return issueScreen()
    case 'syncContacts': return syncScreen()
    default: return done('Unknown request', request.kind)
  }
}

function done(title, body) {
  text('done-title', title)
  text('done-text', body || '')
  show('s-done')
}
$('b-close').onclick = () => window.close()

// ── unlock, create, import ────────────────────────────────────────────────────────────────────
$('f-unlock').onsubmit = async (e) => {
  e.preventDefault()
  err('e-unlock')
  try {
    await rpc('unlock', { passphrase: e.target.elements.passphrase.value })
    e.target.reset()
    await refreshStatus()
    route()
  } catch (x) { err('e-unlock', x) }
}
$('b-unlock-hw').onclick = async () => {
  err('e-unlock')
  try {
    const hw = await rpc('hardware:get')
    const { key, asserted } = await hardware.unlockKey(hw)
    await rpc('unlock:hardware', { key, asserted })
    await refreshStatus()
    route()
  } catch (x) { err('e-unlock', x) }
}
$('l-create').onclick = (e) => { e.preventDefault(); show('s-create') }
// Two doors to the same screen: a fresh profile opens on "create an identity", and a profile that
// has a vault opens on "unlock". A person restoring arrives at whichever of those they are looking
// at, so the link is on both.
const toRestore = (e) => { e.preventDefault(); err('e-restore'); show('s-restore') }
$('l-restore-passkey').onclick = toRestore
$('l-restore-passkey-2').onclick = toRestore
$('l-restore-back').onclick = (e) => { e.preventDefault(); route() }
// A restore is the one path that starts with no vault and ends with one: the passkey holds the root,
// the passphrase seals it here, and the ordinary flow takes over from the next screen on.
$('f-restore').onsubmit = async (e) => {
  e.preventDefault()
  err('e-restore')
  const f = e.target.elements
  if (f.passphrase.value !== f.again.value) return err('e-restore', 'the passphrases differ')
  try {
    if (!hardware.hasWebAuthn()) throw new Error('WebAuthn is not available here')
    const { roots } = await hardware.restoreFrom()
    const out = await rpc('restore:passkey', { roots, passphrase: f.passphrase.value })
    e.target.reset()
    await refreshStatus()
    route()
    err('e-home', out.rebuilt
      ? 'Restored. The certificate was rebuilt from the key, which is the same identity. The ledger and your contacts were not in the backup.'
      : 'Restored. The ledger and your contacts were not in the backup.')
  } catch (x) { err('e-restore', x) }
}
$('l-import').onclick = (e) => { e.preventDefault(); show('s-import') }
$('l-create-back').onclick = (e) => { e.preventDefault(); route() }
$('l-import-back').onclick = (e) => { e.preventDefault(); route() }

$('f-create').onsubmit = async (e) => {
  e.preventDefault()
  err('e-create')
  const f = e.target.elements
  if (f.passphrase.value !== f.again.value) return err('e-create', 'the passphrases differ')
  try {
    const { vault } = await rpc('create', { name: f.name.value, alg: f.alg.value, passphrase: f.passphrase.value })
    await rpc('notice:shown')
    download(`${f.name.value.trim().replace(/[^\w.-]+/g, '-') || 'identity'}.pact-vault.json`, vault)
    e.target.reset()
    await refreshStatus()
    show('s-hardware')
  } catch (x) { err('e-create', x) }
}
$('b-hw-skip').onclick = () => { $('hw-gate').hidden = true; route() }
// Two doors, because "any authenticator" is how a password manager ends up holding a credential it
// cannot derive from: cross-platform is a security key, platform is this device's own.
const hwEnable = (attachment) => async () => {
  err('e-hardware')
  $('hw-gate').hidden = true
  try {
    await enableHardware(attachment)
    route()
  } catch (x) {
    // A credential that can hold nothing is not a failure to report and forget: it is the case a
    // password manager lands in, and the person can still use it as a gate — once they have been
    // told, in the panel below, exactly what that is and is not.
    if (x && x.code === 'no_secret') { offerGate(x) } else { err('e-hardware', x) }
  }
}
$('b-hw-enable').onclick = hwEnable('cross-platform')
$('b-hw-device').onclick = hwEnable('platform')

function offerGate(x) {
  err('e-hardware', x)
  $('hw-gate').hidden = false
  $('b-hw-gate').onclick = async () => {
    err('e-hardware')
    $('hw-gate').hidden = true
    try {
      const { mode, credentialId, key } = await hardware.enrollGate(x.credentialId)
      await rpc('hardware:enable', { mode, credentialId, key })
      await refreshStatus()
      route()
    } catch (e) { err('e-hardware', e) }
  }
}

async function enableHardware(attachment) {
  if (!hardware.hasWebAuthn()) throw new Error('WebAuthn is not available here')
  const root = state.roots[0]
  // No roots here. Enrolment registers a credential and asks it for a secret; it never writes an
  // identity anywhere, and `enroll` takes no roots. Fetching them anyway put every private key in
  // this window's heap on a path that had no use for one — the backup button (`b-backup-passkey`)
  // is the only caller that does, and it is the only one that asks.
  const { mode, credentialId, salt, key } = await hardware.enroll(root ? root.cn : 'pact', attachment)
  await rpc('hardware:enable', { mode, credentialId, salt, key })
  await refreshStatus()
}

$('f-import').onsubmit = async (e) => {
  e.preventDefault()
  err('e-import')
  const f = e.target.elements
  try {
    const vault = JSON.parse(await f.file.files[0].text())
    const out = await rpc('import', { vault, passphrase: f.passphrase.value })
    e.target.reset()
    await refreshStatus()
    route()
    // A vault made by a hosted wallet page names where that page keeps its own sealed copy. This
    // wallet cannot reach it — a WebAuthn credential is bound to its RP ID and this extension's
    // is its own `chrome-extension://` origin, so a `prf` copy's secret cannot be derived here at
    // all — and the honest thing is to say so at the moment somebody would otherwise assume the
    // two are one wallet that both edit. The file is the bridge; it is not a sync.
    if (out && out.hosted) {
      err('e-home', {
        why: out.hosted.mode === 'prf'
          ? 'Imported. The copy PACT Cloud keeps is sealed to a passkey on their site, so this wallet cannot read or change it — from here on these are two separate wallets, and a vault file is how you move between them.'
          : 'Imported. PACT Cloud also keeps a copy of this vault, opened by the same passphrase. This wallet keeps its own and will not change theirs; a vault file is how you move between them.',
      })
    }
  } catch (x) { err('e-import', x) }
}

// ── pick an identity ──────────────────────────────────────────────────────────────────────────
function pick(thenIssue = false) {
  text('pick-origin', request.origin)
  const list = $('pick-list')
  list.innerHTML = ''
  state.roots.forEach((r, i) => {
    const label = document.createElement('label')
    label.className = 'item'
    label.innerHTML = `<input type="radio" name="root" value="${r.fingerprint}" ${i === 0 || r.fingerprint === request.granted ? 'checked' : ''}> <span class="cn"></span> <code class="small"></code>`
    label.querySelector('.cn').textContent = r.cn
    label.querySelector('code').textContent = short(r.fingerprint)
    list.appendChild(label)
  })
  const add = document.createElement('a')
  add.href = '#'
  add.textContent = 'Create a new identity for this'
  add.onclick = (e) => { e.preventDefault(); show('s-create') }
  list.appendChild(add)
  $('f-pick').onsubmit = async (e) => {
    e.preventDefault()
    const root = new FormData(e.target).get('root')
    if (!root) return
    await rpc('grant', { reqId, root })
    if (thenIssue) return handleRequest()
    done('Identity shared', `${request.origin} now knows which identity you are here. Nothing else was shared.`)
  }
  $('b-pick-deny').onclick = async () => { await rpc('deny', { reqId, code: 'denied', why: 'the person declined' }); window.close() }
  show('s-pick')
}

// ── issue ─────────────────────────────────────────────────────────────────────────────────────
function issueScreen() {
  const r = request
  const purpose = r.op || r.purpose || 'issue'
  text('issue-title', { signup: 'Issue the first certificate', renew: 'Renew the certificate', move: 'Move to a new address', upgrade: 'Upgrade this identity to 2.0' }[purpose] || 'Issue a certificate')
  // What agreeing to the facts below actually means, in the words somebody would use. The
  // facts were complete and the sentence was missing, which is a different kind of gap: a
  // person can read every row and still not know what they are about to hand over.
  text('issue-plain', {
    signup: `You are about to let ${r.endpoint} answer for you. It gets a certificate your identity signs — not your identity itself, which never leaves this wallet.`,
    renew: `You are about to give ${r.endpoint} a fresh certificate for another year. Nothing else changes.`,
    move: `You are about to move to ${r.endpoint}. Your contacts follow you there as they see this certificate, and the old address stops being you.`,
    upgrade: `You are about to take ownership of ${r.endpoint}'s existing key — it keeps the key, your identity vouches for it from now on.`,
  }[purpose] || `You are about to sign a certificate for ${r.endpoint}.`)
  text('issue-origin', r.origin)
  text('issue-endpoint', r.endpoint)
  $('issue-newhost').hidden = !r.new_host
  $('issue-newendpoint').hidden = !r.new_endpoint || r.new_host
  const root = state.roots.find((x) => x.fingerprint === r.root)
  text('issue-root', root ? `${root.cn} · ${short(root.fingerprint)}` : short(r.root || ''))
  text('issue-hostkey', r.host_fingerprint)
  text('issue-dates', `${when(r.not_before)} → ${when(r.not_after)} (${r.valid_days} days)`)
  let originHost = ''
  try { originHost = new URL(r.origin).host } catch { /* opaque */ }
  let endpointHost = ''
  try { endpointHost = new URL(r.endpoint).host } catch { /* refused above */ }
  $('issue-mismatch').hidden = !originHost || originHost === endpointHost
  $('issue-move').hidden = !r.move
  $('issue-pass-wrap').hidden = !r.new_endpoint
  const refused = r.refused || null
  $('issue-refused').hidden = !refused
  text('issue-refused', refused || '')
  $('b-sign').disabled = !!refused
  err('e-issue')
  $('f-issue').onsubmit = async (e) => {
    e.preventDefault()
    err('e-issue')
    $('b-sign').disabled = true
    try {
      const out = await rpc('issue', { reqId, root: r.root, passphrase: e.target.elements.passphrase.value })
      e.target.reset()
      done('Certificate issued', `${out.endpoint} holds a certificate from ${root ? root.cn : 'this identity'} until ${when(out.not_after)}.${out.warnings && out.warnings.length ? ' ' + out.warnings.join(' ') : ''}`)
    } catch (x) {
      err('e-issue', x)
      $('b-sign').disabled = false
      if (x.code === 'one_live_leaf' || x.code === 'bad_csr') $('b-sign').disabled = true
    }
  }
  $('b-issue-deny').onclick = async () => { await rpc('deny', { reqId, code: 'denied', why: 'the person declined to sign' }); window.close() }
  if (refused) {
    // Nothing to decide: the page is told now, the person sees why.
    rpc('deny', { reqId, code: 'one_live_leaf', why: refused }).catch(() => {})
  }
  show('s-issue')
}

// ── contacts ──────────────────────────────────────────────────────────────────────────────────
async function syncScreen() {
  text('sync-origin', request.origin)
  const list = $('sync-list')
  list.innerHTML = ''
  const diffs = request.differences || []
  if (!diffs.length) {
    list.textContent = `No differences: the wallet's book and the page's agree (${request.count} contacts).`
  }
  diffs.forEach((d, i) => {
    const label = document.createElement('label')
    label.className = 'item'
    const checked = d.kind !== 'removed'
    const what = d.kind === 'added' ? `add ${d.theirs.name || ''} at ${d.theirs.endpoint}` : d.kind === 'removed' ? `remove ${d.mine.name || ''} (${d.mine.endpoint}) — not in the page's book` : `${d.mine.name || ''}: ${d.mine.endpoint} → ${d.theirs.endpoint}${d.theirs.leaf && d.theirs.leaf !== d.mine.leaf ? ', new certificate' : ''}`
    label.innerHTML = `<input type="checkbox" name="d${i}" ${checked ? 'checked' : ''}> <span class="tag ${d.kind}"></span> <span class="what"></span> <code class="small"></code>`
    label.querySelector('.tag').textContent = d.kind
    label.querySelector('.what').textContent = what
    label.querySelector('code').textContent = short(d.root)
    list.appendChild(label)
  })
  $('f-sync').onsubmit = async (e) => {
    e.preventDefault()
    const { contacts } = await rpc('contacts:get')
    const book = new Map(contacts.map((c) => [c.root, c]))
    const fd = new FormData(e.target)
    diffs.forEach((d, i) => {
      if (!fd.get(`d${i}`)) return
      if (d.kind === 'removed') book.delete(d.root)
      else book.set(d.root, { ...(book.get(d.root) || {}), root: d.root, endpoint: d.theirs.endpoint, name: d.theirs.name || (book.get(d.root) || {}).name || '', leaf: d.theirs.leaf, root_cert: d.theirs.root_cert || (book.get(d.root) || {}).root_cert })
    })
    err('e-sync', null)
    try {
      await rpc('contacts:apply', { reqId, book: [...book.values()] })
    } catch (e) {
      // A book the wallet will not keep — a root certificate that is not the pinned root's, say —
      // is shown here and nothing is written. The page's request stays open: the person can untick
      // the offending row and apply again, or decline.
      err('e-sync', e)
      return
    }
    done('Contacts reconciled', 'The wallet keeps its own copy of your contact book; it outlives any host.')
  }
  $('b-sync-deny').onclick = async () => { await rpc('deny', { reqId, code: 'denied', why: 'the person declined' }); window.close() }
  show('s-sync')
}


// ── a fingerprint, as a shape ─────────────────────────────────────────────────────────────
//
// This product's security model is that people compare fingerprints, and nobody compares 44
// characters of base64 by eye. An identicon is the convention crypto wallets settled on for
// exactly that problem, and it is the one that transfers here unchanged: deterministic from the
// fingerprint, so the same identity is the same mark on every screen it appears on, and a
// changed identity is a changed picture before it is a changed string.
//
// Drawn rather than fetched — a wallet loads nothing from anywhere — and from the fingerprint's
// own bytes, so there is no hash to keep in step with anything.
function identicon(fingerprint, small = false) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  el.setAttribute('viewBox', '0 0 5 5')
  el.setAttribute('class', 'ident' + (small ? ' sm' : ''))
  el.setAttribute('aria-hidden', 'true')
  let h = 2166136261
  for (let i = 0; i < fingerprint.length; i++) { h ^= fingerprint.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0 }
  const hue = h % 360
  const bg = document.createElementNS(el.namespaceURI, 'rect')
  bg.setAttribute('width', '5'); bg.setAttribute('height', '5')
  bg.setAttribute('fill', `hsl(${hue} 32% 92%)`)
  el.appendChild(bg)
  // Mirrored down the middle, which is what makes these read as a face rather than as noise.
  for (let x = 0; x < 3; x++) {
    for (let y = 0; y < 5; y++) {
      h = Math.imul(h ^ (x * 5 + y), 16777619) >>> 0
      if ((h >>> 28) % 2) continue
      for (const col of x === 2 ? [2] : [x, 4 - x]) {
        const r = document.createElementNS(el.namespaceURI, 'rect')
        r.setAttribute('x', String(col)); r.setAttribute('y', String(y))
        r.setAttribute('width', '1'); r.setAttribute('height', '1')
        r.setAttribute('fill', `hsl(${hue} 46% 42%)`)
        el.appendChild(r)
      }
    }
  }
  return el
}

/** Days until an expiry, or null when there is not one. */
function daysUntil(iso) {
  const t = Date.parse(iso || '')
  return Number.isFinite(t) ? Math.ceil((t - Date.now()) / 86400000) : null
}

// ── tabs ──────────────────────────────────────────────────────────────────────────────────
for (const tab of document.querySelectorAll('.tab')) {
  tab.addEventListener('click', () => {
    for (const t of document.querySelectorAll('.tab')) t.classList.toggle('on', t === tab)
    for (const p of document.querySelectorAll('.pane')) p.hidden = p.id !== tab.dataset.tab
  })
}

// ── home ──────────────────────────────────────────────────────────────────────────────────────
async function home() {
  await refreshStatus()

  // ── identities ────────────────────────────────────────────────────────────────────────
  const roots = $('home-roots')
  roots.innerHTML = ''
  for (const r of state.roots) {
    const div = document.createElement('div')
    div.className = 'item'
    div.appendChild(identicon(r.fingerprint))
    const text = document.createElement('div')
    text.className = 'grow'
    text.innerHTML = '<div class="cn"></div><code class="small"></code><div class="muted small"></div>'
    text.querySelector('.cn').textContent = r.cn
    text.querySelector('code').textContent = r.fingerprint
    text.querySelector('.muted').textContent = `${r.alg || ''} · since ${when(r.created)}`
    div.appendChild(text)
    const copy = document.createElement('button')
    copy.className = 'secondary'
    copy.textContent = 'Copy'
    copy.title = 'Copy this fingerprint'
    copy.onclick = () => { navigator.clipboard.writeText(r.fingerprint).catch(() => {}); copy.textContent = 'Copied'; setTimeout(() => { copy.textContent = 'Copy' }, 1200) }
    div.appendChild(copy)
    roots.appendChild(div)
  }

  // ── activity: the ledger, and what it means for the next few weeks ────────────────────
  //
  // Renewal is the one recurring obligation this wallet has, and the old screen mentioned it
  // nowhere — a certificate simply stopped working one day. The soonest expiry is surfaced
  // here and in the health line above, because a renewal is cheap and an expiry is not.
  const ledger = $('home-ledger')
  ledger.innerHTML = ''
  let soonest = null
  for (const r of state.roots) {
    const { entries } = await rpc('ledger', { root: r.fingerprint })
    for (const l of entries) {
      const left = daysUntil(l.not_after)
      const live = !l.superseded_at && left !== null && left > 0
      if (live && (soonest === null || left < soonest)) soonest = left
      const div = document.createElement('div')
      div.className = 'item'
      div.appendChild(identicon(r.fingerprint, true))
      const tag = document.createElement('span')
      tag.className = 'tag ' + (live ? (left <= 30 ? 'warn' : 'live') : 'past')
      tag.textContent = live ? (left <= 30 ? `${left}d left` : 'live') : l.superseded_at ? 'superseded' : 'expired'
      div.appendChild(tag)
      const text = document.createElement('div')
      text.className = 'grow'
      text.innerHTML = '<code></code><div class="muted small"></div>'
      text.querySelector('code').textContent = l.endpoint
      text.querySelector('.muted').textContent = `${when(l.not_before)} → ${when(l.not_after)}${l.origin ? ' · asked by ' + l.origin : ''}`
      div.appendChild(text)
      ledger.appendChild(div)
    }
  }
  if (!ledger.children.length) ledger.textContent = 'No certificate issued yet.'

  // ── connected: who holds a grant right now ────────────────────────────────────────────
  //
  // Grants were an in-memory map nobody could see. A person could not answer "which pages can
  // act as me at this moment", which is the first question anybody asks of a wallet.
  const sites = $('home-sites')
  sites.innerHTML = ''
  const { grants } = await rpc('grants:list')
  for (const g of grants) {
    const root = state.roots.find((r) => r.fingerprint === g.root)
    const div = document.createElement('div')
    div.className = 'item'
    div.appendChild(identicon(g.root, true))
    const text = document.createElement('div')
    text.className = 'grow'
    text.innerHTML = '<div class="origin"></div><div class="muted small"></div>'
    text.querySelector('.origin').textContent = g.origin
    text.querySelector('.muted').textContent = `acting as ${root ? root.cn : short(g.root)}`
    div.appendChild(text)
    const off = document.createElement('button')
    off.className = 'secondary'
    off.textContent = 'Revoke'
    off.onclick = async () => { await rpc('grants:revoke', { origin: g.origin }); home() }
    div.appendChild(off)
    sites.appendChild(div)
  }
  if (!sites.children.length) sites.textContent = 'No page is holding an identity right now.'

  // ── backups: a state, not a row of buttons ────────────────────────────────────────────
  const { contacts } = await rpc('contacts:get')
  text('home-contacts', `${contacts.length} contact${contacts.length === 1 ? '' : 's'} in the wallet's own book.`)
  text('home-passkey', state.passkeyBackup
    ? `Passkey backup: written ${when(state.passkeyBackup.at)}. It holds the root, not the ledger or your contacts.`
    : 'Passkey backup: none on this identity yet.')
  text('home-hw', !state.hardware.enabled
    ? 'Security key: not enabled.'
    : state.hardware.stale
      ? `Security key: ${HW_MODE[state.hardware.mode] || state.hardware.mode}, behind the vault until the next passphrase unlock.`
      : `Security key: ${HW_MODE[state.hardware.mode] || state.hardware.mode}, enabled on this device.`)

  // The nag, and it says the true thing rather than a count of buttons. A vault file that was
  // downloaded is not evidence of anything — the person may never have found it again — so the
  // only copies this claims are the ones the wallet itself can see: a passkey blob and a
  // security key. Everything else is "you may have a file, and we cannot tell".
  const kept = []
  if (state.passkeyBackup) kept.push('a passkey')
  if (state.hardware.enabled) kept.push('a security key')
  const health = $('backup-health')
  health.hidden = false
  health.className = 'health ' + (kept.length ? 'ok' : 'bad')
  health.innerHTML = '<b></b><span></span>'
  if (kept.length) {
    health.querySelector('b').textContent = `Backed up on ${kept.join(' and ')}.`
    health.querySelector('span').textContent = soonest !== null && soonest <= 30
      ? `A certificate expires in ${soonest} days — renew it from the site that holds it.`
      : 'Keep a vault file too: an authenticator can be lost, and the file is what survives that.'
  } else {
    health.querySelector('b').textContent = 'No backup this wallet can see.'
    health.querySelector('span').textContent = 'If this browser profile goes, so does this identity — unless you still have a vault file. Download one now, or put a copy on a passkey.'
  }

  $('f-refresh').hidden = !state.vaultStale
  $('b-backup-drive').hidden = !drive.driveEnabled()
  show('s-home')
}

// Export refuses while the passphrase copy is behind the security key's, and this was the one home
// button that did not say so — it rejected into nothing and looked like a button that does not work.
$('b-backup-file').onclick = async () => {
  err('e-home')
  try { const { vault } = await rpc('export'); download('pact-vault.json', vault) } catch (x) { err('e-home', x) }
}
$('b-backup-import').onclick = () => show('s-import')
$('b-backup-hw').onclick = async () => {
  err('e-home')
  try {
    // Enabling goes to the enrolment screen and its two doors. Calling `enableHardware()` here with
    // no attachment was the same mistake that screen exists to prevent: an unpinned registration is
    // one a password manager can take, which is how a credential that cannot derive a secret ends up
    // holding the wallet's enrolment.
    if (!state.hardware.enabled) { show('s-hardware'); return }
    await rpc('hardware:disable')
    await refreshStatus()
    home()
  } catch (x) {
    // The offer to use a credential as a gate lives on the enrolment screen, with the paragraph
    // that says what it costs; a person who started from home is taken there rather than handed
    // the refusal on its own.
    if (x && x.code === 'no_secret') { show('s-hardware'); offerGate(x) } else { err('e-home', x) }
  }
}
$('b-backup-passkey').onclick = async () => {
  err('e-home')
  try {
    if (!hardware.hasWebAuthn()) throw new Error('WebAuthn is not available here')
    const root = state.roots[0]
    // The roots reach this window for the moment of the write and no longer; a page cannot ask for
    // them, and nothing here keeps a reference once the passkey has them.
    let secrets = await rpc('hardware:secrets')
    try {
      const { roots } = await hardware.backupTo(root ? root.cn : 'pact', secrets.roots)
      await rpc('passkey:noted', { count: roots.length })
    } finally { secrets = null }
    await refreshStatus()
    home()
  } catch (x) { err('e-home', x) }
}
$('b-backup-drive').onclick = async () => {
  err('e-home')
  try {
    const { vault } = await rpc('export')
    await drive.upload(vault)
    text('home-hw', 'Uploaded to Drive app data.')
  } catch (x) { err('e-home', x) }
}
$('f-refresh').onsubmit = async (e) => {
  e.preventDefault()
  err('e-refresh')
  try {
    await rpc('passphrase:refresh', { passphrase: e.target.elements.passphrase.value })
    e.target.reset()
    await refreshStatus()
    home()
  } catch (x) { err('e-refresh', x) }
}
$('b-new-identity').onclick = () => show('s-create')
$('b-lock').onclick = async () => { await rpc('lock'); await refreshStatus(); route() }

start()
