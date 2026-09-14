// The wallet's own window: every grant and every signature happens here, after a click, in a
// window no page can draw over. It talks to the service worker over a port and renders one
// screen at a time from the state and the request it was opened for.
import * as hardware from './hardware.js'
import * as drive from './drive.js'

const port = chrome.runtime.connect({ name: 'window' })
const waiting = new Map()
let n = 0
port.onMessage.addListener((m) => {
  if (m && typeof m.id === 'number' && waiting.has(m.id)) {
    const { resolve, reject } = waiting.get(m.id)
    waiting.delete(m.id)
    if (m.ok) resolve(m.result)
    else reject(Object.assign(new Error(m.error.why || m.error.code), { code: m.error.code }))
    return
  }
  if (m && (m.type === 'locked' || m.type === 'changed' || m.type === 'unlocked')) refreshStatus()
})
function rpc(type, fields = {}) {
  const id = ++n
  return new Promise((resolve, reject) => {
    waiting.set(id, { resolve, reject })
    port.postMessage({ id, type, ...fields })
  })
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
  state = await rpc('state')
  text('status', state.locked ? 'locked' : `${state.roots.length} identit${state.roots.length === 1 ? 'y' : 'ies'} · unlocked`)
  $('status').className = 'pill ' + (state.locked ? 'locked' : 'open')
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
    $('b-unlock-hw').hidden = !(state.hardware.enabled && !state.hardware.stale && hardware.hasWebAuthn())
    return show('s-locked')
  }
  if (!request) return home()
  return handleRequest()
}

async function handleRequest() {
  try { request = await rpc('request', { reqId }) } catch (e) { return done('Request gone', e.message) }
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
    const prfKey = await hardware.evaluate(hw.credentialId, hw.salt)
    await rpc('unlock:hardware', { prfKey })
    await refreshStatus()
    route()
  } catch (x) { err('e-unlock', x) }
}
$('l-create').onclick = (e) => { e.preventDefault(); show('s-create') }
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
$('b-hw-skip').onclick = () => route()
$('b-hw-enable').onclick = async () => {
  err('e-hardware')
  try {
    await enableHardware()
    route()
  } catch (x) { err('e-hardware', x) }
}
async function enableHardware() {
  if (!hardware.hasWebAuthn()) throw new Error('WebAuthn is not available here')
  const root = state.roots[0]
  const { credentialId, salt, prfKey } = await hardware.enroll(root ? root.cn : 'pact')
  await rpc('hardware:enable', { credentialId, salt, prfKey })
  await refreshStatus()
}

$('f-import').onsubmit = async (e) => {
  e.preventDefault()
  err('e-import')
  const f = e.target.elements
  try {
    const vault = JSON.parse(await f.file.files[0].text())
    await rpc('import', { vault, passphrase: f.passphrase.value })
    e.target.reset()
    await refreshStatus()
    route()
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
      else book.set(d.root, { ...(book.get(d.root) || {}), root: d.root, endpoint: d.theirs.endpoint, name: d.theirs.name || (book.get(d.root) || {}).name || '', leaf: d.theirs.leaf })
    })
    await rpc('contacts:apply', { reqId, book: [...book.values()] })
    done('Contacts reconciled', 'The wallet keeps its own copy of your contact book; it outlives any host.')
  }
  $('b-sync-deny').onclick = async () => { await rpc('deny', { reqId, code: 'denied', why: 'the person declined' }); window.close() }
  show('s-sync')
}

// ── home ──────────────────────────────────────────────────────────────────────────────────────
async function home() {
  await refreshStatus()
  const roots = $('home-roots')
  roots.innerHTML = ''
  for (const r of state.roots) {
    const div = document.createElement('div')
    div.className = 'item'
    div.innerHTML = `<span class="cn"></span> <code class="small"></code> <span class="muted"></span>`
    div.querySelector('.cn').textContent = r.cn
    div.querySelector('code').textContent = r.fingerprint
    div.querySelector('.muted').textContent = `${r.alg || ''} · since ${when(r.created)}`
    roots.appendChild(div)
  }
  const ledger = $('home-ledger')
  ledger.innerHTML = ''
  for (const r of state.roots) {
    const { entries } = await rpc('ledger', { root: r.fingerprint })
    for (const l of entries) {
      const div = document.createElement('div')
      div.className = 'item'
      const live = !l.superseded_at && Date.parse(l.not_after) > Date.now()
      div.innerHTML = `<span class="tag ${live ? 'live' : 'past'}"></span> <code></code> <span class="muted"></span>`
      div.querySelector('.tag').textContent = live ? 'live' : l.superseded_at ? 'superseded' : 'expired'
      div.querySelector('code').textContent = l.endpoint
      div.querySelector('.muted').textContent = `${when(l.not_before)} → ${when(l.not_after)}${l.origin ? ' · asked by ' + l.origin : ''}`
      ledger.appendChild(div)
    }
  }
  if (!ledger.children.length) ledger.textContent = 'No certificate issued yet.'
  const { contacts } = await rpc('contacts:get')
  text('home-contacts', `${contacts.length} contact${contacts.length === 1 ? '' : 's'} in the wallet's own book.`)
  text('home-hw', state.hardware.enabled ? (state.hardware.stale ? 'Security key: enabled, behind the vault until the next passphrase unlock.' : 'Security key: enabled on this device.') : 'Security key: not enabled.')
  $('b-backup-drive').hidden = !drive.driveEnabled()
  show('s-home')
}
$('b-backup-file').onclick = async () => { const { vault } = await rpc('export'); download('pact-vault.json', vault) }
$('b-backup-import').onclick = () => show('s-import')
$('b-backup-hw').onclick = async () => {
  err('e-home')
  try {
    if (state.hardware.enabled) { await rpc('hardware:disable') } else { await enableHardware() }
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
$('b-new-identity').onclick = () => show('s-create')
$('b-lock').onclick = async () => { await rpc('lock'); await refreshStatus(); route() }

start()
