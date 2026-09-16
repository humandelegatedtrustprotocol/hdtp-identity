// The one measurement the passkey-derived-root design rests on: is a passkey's PRF output the same
// on a second device?
//
// Everything else about that design was verified earlier — `prf.eval` answers with an empty
// `allowCredentials`, and it returns the same secret across two assertions on ONE machine, and
// `key_from_seed` turns the same seed into the same key and therefore the same root fingerprint.
// What none of that shows is whether a provider carries the PRF secret across its own sync. Apple,
// Google and 1Password each implement PRF themselves, so each is a separate answer and one tells you
// nothing about the others.
//
// So: derive, print the fingerprint, and compare the string on the other device by eye. A page
// cannot answer this for you, because the second device is the experiment.
//
// Nothing is stored and nothing is sent. The derivation is the real one — the same salt the wallet
// uses and the same `key_from_seed` the core exposes — so a match here is a match in production.

const SALT_INFO = 'pact/vault/1'
const ROOT_INFO = 'pact/root/1'

const $ = (id) => document.getElementById(id)
const enc = new TextEncoder()

const b64u = (bytes) => {
  let s = ''
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
const b64ToBytes = (b64) => {
  const s = atob(b64)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
const challenge = () => crypto.getRandomValues(new Uint8Array(32))

function core(name, args) {
  const out = JSON.parse(call(name, JSON.stringify(args ?? {})))
  if (out && typeof out === 'object' && typeof out.error === 'string' && !('ok' in out)) {
    throw new Error(`${name}: ${out.why || out.error}`)
  }
  return out
}

function fail(text) {
  $('err').textContent = text
  $('err').hidden = false
  $('out').hidden = true
}

/** The PRF secret for this origin's passkey, or null when the authenticator has none. */
async function prfSecret({ create }) {
  const salt = await sha256(enc.encode(SALT_INFO))
  if (create) {
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { name: 'PACT PRF check', id: location.hostname },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'prf-check', displayName: 'PACT PRF check' },
        challenge: challenge(),
        pubKeyCredParams: [-7, -257].map((alg) => ({ type: 'public-key', alg })),
        // Discoverable, because the second device must be able to find it with nothing to go on —
        // which is exactly the situation the design depends on.
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        extensions: { prf: {} },
      },
    })
    const ext = cred.getClientExtensionResults()
    if (!ext.prf || ext.prf.enabled === false) return { secret: null, credentialId: b64u(cred.rawId), why: 'this authenticator says it cannot do PRF at all' }
    // Measured earlier: no authenticator evaluates PRF during registration, so the secret always
    // comes from an assertion straight afterwards.
  }

  // An empty allow list on purpose: the provider offers whatever it holds for this origin, which is
  // how a second device finds a synced passkey.
  const ask = async (allow) => {
    const a = await navigator.credentials.get({
      publicKey: {
        challenge: challenge(),
        allowCredentials: allow ? [{ type: 'public-key', id: allow }] : [],
        userVerification: 'required',
        extensions: { prf: { eval: { first: salt } } },
      },
    })
    const ext = a.getClientExtensionResults()
    return { raw: new Uint8Array(a.rawId), first: ext.prf && ext.prf.results && ext.prf.results.first }
  }

  const one = await ask(null)
  if (one.first) return { secret: new Uint8Array(one.first), credentialId: b64u(one.raw), salt }
  // Some implementations evaluate only when the credential is named; `evalByCredential` is refused
  // outright with an empty allow list, so the second ask names what the first one found.
  const two = await ask(one.raw)
  if (two.first) return { secret: new Uint8Array(two.first), credentialId: b64u(two.raw), salt }
  return { secret: null, credentialId: b64u(one.raw), salt, why: 'this passkey verified you and returned no PRF output' }
}

/** The design's derivation, exactly: HKDF over the PRF secret, then the core's own key. */
async function deriveRoot(secret) {
  const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(ROOT_INFO) },
    ikm,
    256,
  )
  const seed = b64u(bits)
  const key = core('key_from_seed', { alg: 'ed25519', seed })
  // A fixed `not_before`, because the fingerprint must depend on the KEY and nothing else — a
  // timestamp in here would make two runs differ for a reason that has nothing to do with the
  // question being asked.
  const root = core('build_root', { cn: 'PRF check', pkcs8: key.pkcs8, not_before: '2026-01-01T00:00:00Z' })
  return root.fingerprint
}

/**
 * What just happened, against what happened last time — because the two failures this page exists
 * to tell apart look identical on screen and mean opposite things.
 *
 * A DIFFERENT CREDENTIAL producing a different identity is correct: it is a different key. That is
 * the likely case in practice, and it showed up on the first real run of this page — a profile with
 * more than one passkey for the origin, where `allowCredentials: []` lets the provider choose and it
 * chose the other one. Reading that as "PRF is unstable" would condemn a provider for working.
 *
 * The SAME CREDENTIAL producing a different secret is the fatal one, and the only one that says
 * anything about the provider.
 */
function verdict(fingerprint, credentialId) {
  const prevFp = ($('prev-fp').value || '').trim()
  const prevCred = ($('prev-cred').value || '').trim()
  if (!prevFp && !prevCred) {
    return 'Copy the fingerprint and the credential above, then open this page on the other device or profile, press "Use a passkey I already have", and paste both into "Compare with a previous run". Comparing by eye works too, but the credential is the line that decides what a difference means.'
  }
  const sameCred = prevCred && prevCred === credentialId
  const sameFp = prevFp && prevFp === fingerprint
  if (sameCred && sameFp) {
    return 'SAME PASSKEY, SAME IDENTITY. This provider carried the PRF secret across, and a derived identity is safe on it — which is the answer the design needed.'
  }
  if (sameCred && !sameFp) {
    return 'SAME PASSKEY, DIFFERENT IDENTITY. This is the fatal one: the provider gave a different PRF secret for the same credential, so a person would silently become somebody else. A derived identity is not safe on this provider.'
  }
  if (!sameCred && prevCred) {
    return 'A DIFFERENT PASSKEY answered this time — look at the credential line. A different key is a different identity, so this says nothing about whether the provider carries PRF across. Run it again and pick the same passkey; if this profile holds more than one for this origin, that is the thing to fix rather than the provider.'
  }
  return sameFp
    ? 'Same identity, and no previous credential to compare against. Paste the credential line too and the answer stops being ambiguous.'
    : 'A different identity, and no previous credential to compare against — so this could be a different passkey (fine) or the same one giving a different secret (fatal). Paste the credential line from the other run to tell which.'
}

async function run(create) {
  $('err').hidden = true
  $('out').hidden = true
  for (const b of ['create', 'use']) $(b).disabled = true
  try {
    const { secret, credentialId, salt, why } = await prfSecret({ create })
    if (!secret) {
      fail(`No PRF from this authenticator — ${why}. That provider cannot carry a derived identity, and the design's no-PRF path is what such a person would get instead.`)
      return
    }
    const fingerprint = await deriveRoot(secret)
    $('fingerprint').textContent = fingerprint
    $('prf').textContent = b64u(secret)
    $('cred').textContent = credentialId
    $('salt').textContent = b64u(salt)
    $('verdict').textContent = verdict(fingerprint, credentialId)
    $('out').hidden = false
  } catch (e) {
    fail(e && e.name === 'NotAllowedError'
      ? 'No passkey answered — either there is none for this origin yet, or the prompt was dismissed. On a second device, make sure the provider that holds the passkey is available here.'
      : String((e && (e.message || e.name)) || e))
  } finally {
    for (const b of ['create', 'use']) $(b).disabled = false
  }
}

$('create').addEventListener('click', () => run(true))
$('use').addEventListener('click', () => run(false))

;(() => {
  if (!window.PublicKeyCredential) return fail('This browser has no WebAuthn, so there is nothing to measure here.')
  try {
    initSync({ module: b64ToBytes(WASM_B64) })
  } catch (e) {
    fail('the identity core could not start: ' + String(e))
  }
})()
