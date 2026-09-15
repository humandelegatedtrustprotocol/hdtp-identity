// The toolbar popup: status at a glance, a door to the window, and a lock.
// The worker sleeps when it is quiet and takes every port with it, so the port is made on demand
// and remade when it has gone (window.js says more).
let port = null
const waiting = new Map()
let n = 0
function livePort() {
  if (port) return port
  port = chrome.runtime.connect({ name: 'popup' })
  port.onMessage.addListener(onMessage)
  port.onDisconnect.addListener(onDisconnect)
  return port
}
function onMessage(m) {
  if (m && typeof m.id === 'number' && waiting.has(m.id)) {
    const { resolve, reject } = waiting.get(m.id)
    waiting.delete(m.id)
    m.ok ? resolve(m.result) : reject(new Error(m.error.why || m.error.code))
  } else if (m && (m.type === 'locked' || m.type === 'changed' || m.type === 'unlocked')) render()
}
const rpc = (type, fields = {}) => new Promise((resolve, reject) => {
  const id = ++n
  waiting.set(id, { resolve, reject })
  try {
    livePort().postMessage({ id, type, ...fields })
  } catch {
    port = null
    try { livePort().postMessage({ id, type, ...fields }) } catch (e) { waiting.delete(id); reject(e) }
  }
})

// A call in flight when the worker stops is lost; the next one reconnects.
function onDisconnect() {
  port = null
  const gone = Object.assign(new Error('the wallet was locked; open this popup again'), { code: 'disconnected' })
  for (const { reject } of waiting.values()) reject(gone)
  waiting.clear()
}

async function render() {
  const s = await rpc('state')
  const status = document.getElementById('status')
  status.textContent = s.locked ? (s.hasVault ? 'locked' : 'no identity yet') : 'unlocked'
  status.className = 'pill ' + (s.locked ? 'locked' : 'open')
  const roots = document.getElementById('roots')
  roots.innerHTML = ''
  for (const r of s.roots) {
    const div = document.createElement('div')
    div.className = 'item'
    div.innerHTML = '<span class="cn"></span> <code class="small"></code>'
    div.querySelector('.cn').textContent = r.cn
    div.querySelector('code').textContent = r.fingerprint.slice(0, 15) + '…'
    roots.appendChild(div)
  }
  document.getElementById('b-lock').hidden = s.locked
}
document.getElementById('b-open').onclick = () => chrome.windows.create({ url: chrome.runtime.getURL('window.html'), type: 'popup', focused: true, width: 480, height: 680 })
document.getElementById('b-lock').onclick = async () => { await rpc('lock'); render() }
render()
