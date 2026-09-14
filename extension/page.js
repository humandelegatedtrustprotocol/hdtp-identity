// Page script, MAIN world: `window.pact`, the wallet as a page sees it. Every call is a
// promise answered only after the person has acted in the wallet's own window. The page never
// sees the vault, a root key, or another identity's ledger — only what it asked for.
//
// The sign-up ceremony speaks the same messages to the extension as to the provider's frame:
// post `{pact: 'ceremony/1', op: 'signup' | 'renew' | 'move' | 'upgrade', csr, endpoint,
// display_name, new_host}` to the page's own window (or call `window.pact.ceremony(msg)`), and
// `{pact: 'ceremony/1', op: 'leaf', chain, root_fingerprint}` comes back the same way.
;(() => {
  if (window.pact && window.pact.__wallet) return
  const TAG = '__pact_wallet'
  const waiting = new Map()
  let n = 0

  window.addEventListener('message', (event) => {
    if (event.source !== window) return
    const d = event.data
    if (!d || typeof d !== 'object') return
    if (d[TAG] === 'response' && waiting.has(d.id)) {
      const { resolve, reject } = waiting.get(d.id)
      waiting.delete(d.id)
      if (d.ok) resolve(d.result)
      else reject(Object.assign(new Error(d.error && d.error.why ? d.error.why : 'refused'), { code: d.error && d.error.code ? d.error.code : 'refused' }))
      return
    }
    if (d.pact === 'ceremony/1' && ['signup', 'renew', 'move', 'upgrade'].includes(d.op)) {
      ceremony(d).then(
        (r) => window.postMessage({ pact: 'ceremony/1', op: 'leaf', chain: r.chain, root_fingerprint: r.root_fingerprint, not_after: r.not_after }, '*'),
        (e) => window.postMessage({ pact: 'ceremony/1', op: e.code === 'cancelled' || e.code === 'denied' ? 'cancel' : 'error', why: e.message }, '*'),
      )
    }
  })

  function send(op, args) {
    const id = 'p' + (++n) + '-' + Math.random().toString(36).slice(2, 10)
    return new Promise((resolve, reject) => {
      waiting.set(id, { resolve, reject })
      window.postMessage({ [TAG]: 'request', id, op, args }, '*')
    })
  }

  function ceremony(msg) {
    return send('ceremony', { op: msg.op, csr: msg.csr, endpoint: msg.endpoint, display_name: msg.display_name, new_host: !!msg.new_host })
  }

  const pact = Object.freeze({
    __wallet: true,
    version: '0.1.0',
    /** → {root_fingerprint, cn} after the person picks an identity for this origin. */
    requestIdentity: () => send('requestIdentity', {}),
    /** csr: base64url PKCS #10 → {chain: [leaf, root], root_fingerprint, endpoint, not_after} after Sign. */
    issueCertificate: (csr, opts) => send('issueCertificate', { csr, notAfter: opts && opts.notAfter, move: !!(opts && opts.move) }),
    /** The ledger of the identity granted to this origin. */
    listCertificates: () => send('listCertificates', {}),
    /** contacts: [{root, endpoint, name, leaf?}] → the wallet's book after the person reconciles. */
    syncContacts: (contacts) => send('syncContacts', { contacts }),
    ceremony,
  })
  Object.defineProperty(window, 'pact', { value: pact, writable: false, configurable: false })
})()
