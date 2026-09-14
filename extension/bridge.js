// Content script, isolated world: the one door between a page and the wallet. It relays the
// page's requests to the service worker with the page's origin attached by Chrome itself
// (sender.origin), never by the page, and relays the answers back. It reads nothing else.
;(() => {
  const TAG = '__pact_wallet'
  window.addEventListener('message', (event) => {
    if (event.source !== window) return
    const d = event.data
    if (!d || typeof d !== 'object' || d[TAG] !== 'request' || typeof d.id !== 'string') return
    const reply = (payload) => window.postMessage({ [TAG]: 'response', id: d.id, ...payload }, '*')
    let sent
    try {
      sent = chrome.runtime.sendMessage({ type: 'page', op: d.op, args: d.args })
    } catch (e) {
      reply({ ok: false, error: { code: 'unavailable', why: 'the wallet is not reachable: ' + (e && e.message) } })
      return
    }
    Promise.resolve(sent).then(
      (answer) => reply(answer && typeof answer === 'object' ? answer : { ok: false, error: { code: 'unavailable', why: 'no answer from the wallet' } }),
      (e) => reply({ ok: false, error: { code: 'unavailable', why: 'the wallet is not reachable: ' + (e && e.message) } }),
    )
  })
})()
