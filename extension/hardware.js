// The hardware wrap: a FIDO2 credential with the PRF extension derives, from a stored salt, a
// 32-byte secret only the authenticator can produce. That secret (base64url) is the passphrase of
// a second sealed copy of the vault, so a security key or a platform passkey can replace the
// passphrase on this device. Nothing about the vault reaches the authenticator.
import { b64u } from './core.js'

const RP = { id: undefined, name: 'PACT wallet' } // rpId defaults to this extension's origin

export const hasWebAuthn = () => typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials

function challenge() { return crypto.getRandomValues(new Uint8Array(32)) }

/** Registers a credential and derives the PRF output for a fresh salt. */
export async function enroll(userName) {
  const salt = crypto.getRandomValues(new Uint8Array(32))
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: RP,
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: userName || 'pact', displayName: userName || 'PACT wallet' },
      challenge: challenge(),
      pubKeyCredParams: [{ type: 'public-key', alg: -8 }, { type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      extensions: { prf: { eval: { first: salt } } },
    },
  })
  const ext = cred.getClientExtensionResults()
  let first = ext.prf && ext.prf.results && ext.prf.results.first
  const credentialId = b64u.encode(new Uint8Array(cred.rawId))
  if (!first) {
    // Some authenticators enable PRF at create() but only evaluate it at get(); ask once more.
    first = await evaluate(credentialId, b64u.encode(salt))
    return { credentialId, salt: b64u.encode(salt), prfKey: first }
  }
  if (!(ext.prf && ext.prf.enabled !== false)) throw new Error('this authenticator does not support the PRF extension')
  return { credentialId, salt: b64u.encode(salt), prfKey: b64u.encode(new Uint8Array(first)) }
}

/** Re-derives the PRF output for a stored credential and salt. */
export async function evaluate(credentialId, salt) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      rpId: RP.id,
      challenge: challenge(),
      allowCredentials: [{ type: 'public-key', id: b64u.decode(credentialId) }],
      userVerification: 'preferred',
      extensions: { prf: { eval: { first: b64u.decode(salt) } } },
    },
  })
  const ext = assertion.getClientExtensionResults()
  const first = ext.prf && ext.prf.results && ext.prf.results.first
  if (!first) throw new Error('the authenticator returned no PRF output')
  return b64u.encode(new Uint8Array(first))
}
