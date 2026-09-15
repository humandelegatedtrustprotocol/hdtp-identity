// What an authenticator does for this wallet, which is two separate questions.
//
// The fact that shapes both: WebAuthn signs `authenticatorData ‖ SHA-256(clientDataJSON)` and never
// bytes you hand it, so a passkey cannot BE the root — it cannot sign a certificate. A passkey can
// hold a secret, or derive one, or neither; it can never be the signer.
//
// **Unlocking this device**, `enroll`/`unlockKey`, in this order:
//   prf   the authenticator derives a stable 32 bytes from a stored salt (CTAP2 hmac-secret): the
//         passphrase of a second sealed copy of the vault. Two things are then needed, the vault
//         file being the other, so it fails closed if only one of them is taken.
//   gate  no PRF — 1Password and many passkey providers land here. A random key is kept in this
//         profile and used only after the credential answers: a gate on the flow, not a secret at
//         rest. The wallet says so before it is chosen.
//
// **Backing the identity up**, `backupTo`/`restoreFrom`: a largeBlob credential of its own holds
// the root key, which is the whole identity — the fingerprint contacts pin is of its public key
// (SPEC §2), so a certificate rebuilt from it is the same identity and every pin still matches. It
// is a backup and not a live key store: you import from it once to set a machine up, and the
// extension is the working wallet from then on. The exposure is worth stating once: whoever can
// use that credential can restore the identity anywhere, and so can become that person.
import { b64u } from './core.js'

const RP = { id: undefined, name: 'PACT wallet' } // rpId defaults to this extension's origin

export const hasWebAuthn = () => typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials

function challenge() { return crypto.getRandomValues(new Uint8Array(32)) }
const fresh32 = () => crypto.getRandomValues(new Uint8Array(32))
const utf8 = new TextEncoder()
const fromUtf8 = new TextDecoder()
/** The root keys without their certificates: the identity, when a blob will not hold more. */
const keysOnly = (roots) => Object.fromEntries(Object.entries(roots || {}).map(([fp, r]) => [fp, typeof r === 'string' ? r : r.pkcs8]))

/** Thrown when a credential registered but can hold nothing; carries the id, so a gate can reuse it. */
export class NoSecret extends Error {
  constructor(credentialId, why) {
    super(why)
    this.code = 'no_secret'
    this.credentialId = credentialId
  }
}

/**
 * Registers one credential and asks it, in one gesture, for the most it can give.
 *
 * Resolves `{ mode, credentialId, salt, key }`, or throws `NoSecret` carrying the credential it
 * made, which `enrollGate` can still use if the person accepts what that costs.
 */
export async function enroll(userName, attachment) {
  const salt = fresh32()
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: RP,
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: userName || 'pact', displayName: userName || 'PACT wallet' },
      challenge: challenge(),
      // Ed25519 first, because it is what the rest of this wallet speaks, then the two Chrome asks
      // every request to carry — ES256 and RS256 — so an authenticator that knows neither of the
      // first two still registers instead of failing at the last moment.
      pubKeyCredParams: [-8, -7, -257].map((alg) => ({ type: 'public-key', alg })),
      // A secret comes only from a person the authenticator has verified: "preferred" lets that be
      // skipped, and then both extensions answer with nothing at all.
      //
      // Where the credential lives is the person's choice, and it matters: a password manager that
      // offers itself as a passkey provider will take a registration meant for a security key.
      // "cross-platform" is a security key, "platform" this device's own authenticator.
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
        ...(attachment ? { authenticatorAttachment: attachment } : {}),
      },
      // PRF is enabled here, never evaluated: most authenticators — Chrome's own platform one
      // included — refuse to evaluate a salt during registration and answer with `enabled` alone.
      extensions: { prf: {} },
    },
  })
  const ext = cred.getClientExtensionResults()
  const credentialId = b64u.encode(new Uint8Array(cred.rawId))

  if (ext.prf && ext.prf.enabled !== false) {
    // A few evaluate at registration; the rest are asked once more, in the same gesture.
    const atCreate = ext.prf.results && ext.prf.results.first
    const key = atCreate ? b64u.encode(new Uint8Array(atCreate)) : await prfEvaluate(credentialId, b64u.encode(salt))
    return { mode: 'prf', credentialId, salt: b64u.encode(salt), key }
  }

  // It registered, so something answered; it just cannot hold a secret. The likeliest something is
  // a password manager that took the request, which is worth naming rather than leaving the person
  // to guess at "this authenticator".
  throw new NoSecret(credentialId, 'this passkey cannot derive a secret: it does not support PRF')
}

/**
 * Completes the weakest mode with a credential `enroll` already registered. The key is generated
 * here and kept by the wallet; the credential only gates its use. The caller must have told the
 * person what that means before calling this.
 */
export async function enrollGate(credentialId) {
  await assertWith(credentialId, {}) // it answers once before it guards anything
  return { mode: 'gate', credentialId, key: b64u.encode(fresh32()) }
}

/**
 * Re-derives what a stored record needs. `prf` returns the authenticator's 32 bytes; `gate` returns
 * no key, having proved the credential answered — that key is the wallet's own, and the service
 * worker holds it.
 */
export async function unlockKey({ mode, credentialId, salt }) {
  if (mode === 'prf') return { key: await prfEvaluate(credentialId, salt) }
  if (mode === 'gate') { await assertWith(credentialId, {}); return { key: null, asserted: true } }
  throw new Error(`unknown hardware mode ${mode}`)
}

/** PRF: the authenticator's own derivation for our salt. */
async function prfEvaluate(credentialId, salt) {
  const ext = await assertWith(credentialId, { prf: { eval: { first: b64u.decode(salt) } } })
  const first = ext.prf && ext.prf.results && ext.prf.results.first
  // Typed, and carrying the credential: an authenticator that says it supports PRF at registration
  // and then evaluates to nothing is exactly the case the gate offer exists for — a password
  // manager, most often. A plain Error here reached the window with no `code`, so the offer that
  // would have let the person carry on was never made and they were left at a dead end.
  if (!first) {
    throw new NoSecret(credentialId, ext.prf
      ? 'the authenticator verified you but returned no PRF output: this credential cannot hold the wallet\'s secret'
      : 'this authenticator does not support the PRF extension')
  }
  return b64u.encode(new Uint8Array(first))
}

async function writeBlob(credentialId, bytes) {
  const ext = await assertWith(credentialId, { largeBlob: { write: bytes } })
  return !!(ext.largeBlob && ext.largeBlob.written === true)
}

// ── the backup: a credential of its own, holding the identity ────────────────────────────────────

/**
 * Writes the roots to a NEW largeBlob credential — its own, because the passkey a person wants to
 * keep a backup in (an iCloud or password-manager passkey, which may sync) is rarely the one they
 * want to unlock with (a security key). Discoverable, so a fresh profile can find it with nothing
 * stored to go on.
 *
 * `roots` is `{ fingerprint: { pkcs8, cn, cert, created } }`. The certificate is written when the
 * blob takes it and dropped when it will not: the key alone is the identity, and a certificate
 * rebuilt from it hashes to the same fingerprint.
 */
export async function backupTo(userName, roots) {
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: RP,
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: `${userName || 'pact'} (backup)`, displayName: `PACT backup — ${userName || 'identity'}` },
      challenge: challenge(),
      pubKeyCredParams: [-8, -7, -257].map((alg) => ({ type: 'public-key', alg })),
      // Required, both of them: a blob needs a discoverable credential, and a restore on a machine
      // that has never seen this wallet has no credential id to ask for.
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      extensions: { largeBlob: { support: 'required' } },
    },
  })
  const ext = cred.getClientExtensionResults()
  const credentialId = b64u.encode(new Uint8Array(cred.rawId))
  if (!ext.largeBlob || !ext.largeBlob.supported) {
    throw new NoSecret(credentialId, 'this passkey cannot store a backup: it does not support large blobs. A password manager that cannot do this can still keep the vault FILE, which is the whole backup')
  }
  // WebAuthn reports no capacity, so the fuller thing is written and the leaner one tried when the
  // authenticator refuses it.
  let written = false
  for (const body of [{ v: 1, roots }, { v: 1, roots: keysOnly(roots) }]) {
    const payload = utf8.encode(JSON.stringify(body))
    written = await writeBlob(credentialId, payload)
    payload.fill(0)
    if (written) break
  }
  if (!written) throw new NoSecret(credentialId, 'this passkey offered to store a backup and then would not')
  return { credentialId, roots: Object.keys(roots || {}) }
}

/**
 * Reads a backup back with no credential id to go on: the blob's credential is discoverable, so the
 * person picks it from whatever their platform offers. Returns `{ roots }` — each either the full
 * record or the key alone, which the caller rebuilds a certificate from.
 */
export async function restoreFrom() {
  const assertion = await navigator.credentials.get({
    publicKey: {
      rpId: RP.id,
      challenge: challenge(),
      allowCredentials: [], // discoverable: the platform offers what it has for this origin
      userVerification: 'required',
      extensions: { largeBlob: { read: true } },
    },
  })
  const ext = assertion.getClientExtensionResults()
  const blob = ext.largeBlob && ext.largeBlob.blob
  if (!blob) throw new Error('that passkey is not holding a backup of this wallet')
  let parsed
  try { parsed = JSON.parse(fromUtf8.decode(new Uint8Array(blob))) } catch { throw new Error('what that passkey held is not a wallet backup') }
  if (!parsed || !parsed.roots || !Object.keys(parsed.roots).length) throw new Error('what that passkey held is not a wallet backup')
  return { roots: parsed.roots }
}

async function assertWith(credentialId, extensions) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      rpId: RP.id,
      challenge: challenge(),
      allowCredentials: [{ type: 'public-key', id: b64u.decode(credentialId) }],
      // Required, for the reason registration gives: without verification there is no secret to
      // derive from, and the extensions come back empty.
      userVerification: 'required',
      extensions,
    },
  })
  return assertion.getClientExtensionResults()
}
