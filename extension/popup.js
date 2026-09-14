// The toolbar popup: status at a glance, a door to the window, and a lock.
const port = chrome.runtime.connect({ name: 'popup' })
const waiting = new Map()
let n = 0
port.onMessage.addListener((m) => {
  if (m && typeof m.id === 'number' && waiting.has(m.id)) {
    const { resolve, reject } = waiting.get(m.id)
    waiting.delete(m.id)
    m.ok ? resolve(m.result) : reject(new Error(m.error.why || m.error.code))
  } else if (m && (m.type === 'locked' || m.type === 'changed' || m.type === 'unlocked')) render()
})
const rpc = (type, fields = {}) => new Promise((resolve, reject) => { const id = ++n; waiting.set(id, { resolve, reject }); port.postMessage({ id, type, ...fields }) })

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
