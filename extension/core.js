// The identity core (Rust, compiled to WebAssembly), loaded once per context. Bytes in, JSON out.
import init, { call as rawCall } from './vendor/pact_identity_wasm.js'

let ready = null

export class CoreError extends Error {
  constructor(code, why) {
    super(why || code)
    this.code = code
    this.why = why
  }
}

export async function load() {
  if (!ready) ready = init({ module_or_path: chrome.runtime.getURL('vendor/pact_identity_wasm_bg.wasm') })
  await ready
}

/** call('validate_chain', {chain, now}) → parsed object; throws CoreError on {error, why}. */
export async function call(name, args) {
  await load()
  const out = JSON.parse(rawCall(name, JSON.stringify(args ?? {})))
  if (out && typeof out === 'object' && typeof out.error === 'string' && !('ok' in out)) throw new CoreError(out.error, out.why)
  return out
}

export const b64u = {
  encode(bytes) {
    let s = ''
    for (const b of bytes) s += String.fromCharCode(b)
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  },
  decode(text) {
    const s = atob(text.replace(/-/g, '+').replace(/_/g, '/'))
    const out = new Uint8Array(s.length)
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
    return out
  },
}

export const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
