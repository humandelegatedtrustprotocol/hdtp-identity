// §1 of the contract: keys — generate, derive, read, sign, verify.
import { b64url } from '../../../pact-protocol/vectors/lib/keys.mjs';
import { read as derRead, children as derChildren, tlv as derTlv, seq as derSeq } from '../../../pact-protocol/vectors/lib/der.mjs';

export default function keys({ add, expect }, f) {
  const { shape, hostSpki, hostPkcs8, p256Pkcs8, p256Spki, rsaSpki, B64_BAD } = f;
  const keyShape = (a) => (a?.pkcs8 ? { ...a, pkcs8: shape(a.pkcs8), spki: shape(a.spki), fingerprint: shape(a.fingerprint) } : a);
  add('generate_key', 'generate_key', { alg: 'ed25519' }, keyShape);
  add('generate_key of a P-256 key', 'generate_key', { alg: 'p256' }, keyShape);
  add('generate_key with no algorithm', 'generate_key', {});
  add('generate_key with an algorithm nobody has', 'generate_key', { alg: 'rsa' });
  add('key_from_seed with a short seed', 'key_from_seed', { alg: 'ed25519', seed: b64url(new Uint8Array(8)) });
  // §2.1's two refusals. Both matter more than an ordinary argument check: a port that accepted them
  // would return 32 perfectly good bytes belonging to nobody, and the caller would become a different
  // identity without an error anywhere.
  add('derive_seed with an info string that is not one of the three', 'derive_seed', { prf: b64url(new Uint8Array(32)), info: 'pact/root/2' });
  add('derive_seed with the wrong case in the domain separator', 'derive_seed', { prf: b64url(new Uint8Array(32)), info: 'pact/Root/1' });
  add('derive_seed with a short prf', 'derive_seed', { prf: b64url(new Uint8Array(31)), info: 'pact/root/1' });
  add('derive_seed with no info', 'derive_seed', { prf: b64url(new Uint8Array(32)) });
  add('derive_seed with no prf', 'derive_seed', { info: 'pact/root/1' });
  add('derive_seed with prf as null', 'derive_seed', { prf: null, info: 'pact/root/1' });
  add('derive_seed with prf that is not base64url', 'derive_seed', { prf: '!!!', info: 'pact/root/1' });
  add('key_from_seed with an unknown algorithm', 'key_from_seed', { alg: 'rsa', seed: b64url(new Uint8Array(32)) });
  // Bytes of the wrong type answer as bytes that will not decode (CONTRACT §0), as `spki: 123` does
  // above: both ports read a seed of 7 as no seed at all, `seed is required`.
  add('key_from_seed with a seed that is not a string', 'key_from_seed', { alg: 'ed25519', seed: 7 });
  expect('key_from_seed with a seed that is not a string', { error: 'parse', why: 'not base64url' });
  add('public_key of a key that is not one', 'public_key', { pkcs8: b64url(new Uint8Array(16)) });
  add('public_key with no argument', 'public_key', {});
  add('key_info of an spki that is not one', 'key_info', { spki: b64url(new Uint8Array(4)) });
  add('key_info with no argument', 'key_info', {});
  for (const bad of B64_BAD) add(`key_info of bytes that are not base64url (${JSON.stringify(bad)})`, 'key_info', { spki: bad });
  add('key_info of a number', 'key_info', { spki: 123 });
  // 127 containers deep reaches the function, which refuses a list for bytes; 128 is refused before
  // (R40's limit, S3-2). The nesting is written, not raw: JSON.stringify can write it.
  const nested = (n) => JSON.parse('['.repeat(n) + '1' + ']'.repeat(n));
  add('key_info of an spki nested 126 deep, 127 with the arguments', 'key_info', { spki: nested(126) });
  expect('key_info of an spki nested 126 deep, 127 with the arguments', { error: 'parse', why: 'not base64url' });
  add('key_info of an spki nested 127 deep, 128 with the arguments', 'key_info', { spki: nested(127) });
  expect('key_info of an spki nested 127 deep, 128 with the arguments', { error: 'bad_request', why: 'args: nested more than 127 deep' });
  add('sign with a public key', 'sign', { pkcs8: hostSpki, data: b64url(new Uint8Array(4)) });
  add('sign with no data', 'sign', { pkcs8: hostPkcs8 });
  add('verify a signature that is not one', 'verify', { spki: hostSpki, data: b64url(new Uint8Array(4)), sig: b64url(new Uint8Array(4)) });
  add('verify with an empty signature', 'verify', { spki: hostSpki, data: b64url(new Uint8Array(4)), sig: '' });

  // A key whose algorithm the profile does not admit: it must be refused by name.
  add('key_info of an RSA key', 'key_info', { spki: rsaSpki });
  add('public_key of an RSA key', 'public_key', { pkcs8: rsaSpki });
  // `verify` declares `unsupported`, and nothing produced it until the coverage gate asked (TC-1).
  add('verify with an RSA key', 'verify', { spki: rsaSpki, data: b64url(new Uint8Array(4)), sig: b64url(new Uint8Array(4)) });

  // Every member that is absent rather than empty, which is the distinction a port loses when its
  // zero value and its missing value are the same thing.
  for (const fn of ['key_info', 'public_key', 'sign', 'verify', 'generate_key', 'key_from_seed']) add(`${fn} with nothing to work from`, fn, {});
  // The same member present as the JSON literal `null`, which a decoder can quietly read as empty.
  add('key_info with spki as null', 'key_info', { spki: null, presented: f.leafDer, now: f.now });

  // ── one succeeding, whole-answer case per function ─────────────────────────────────────────────
  // The runner insists on these. A refusal compared whole proves both ports refuse alike; only a
  // success compares the members a caller actually reads, which is where a member goes missing.
  const SEED32 = b64url(new Uint8Array(32).fill(11));
  add('key_from_seed', 'key_from_seed', { alg: 'ed25519', seed: SEED32 });
  add('prf_salt', 'prf_salt', {});
  for (const info of ['pact/root/1', 'pact/store-key/1', 'pact/store-id/1']) add(`derive_seed for ${info}`, 'derive_seed', { prf: SEED32, info });
  add('key_from_seed of a P-256 key', 'key_from_seed', { alg: 'p256', seed: SEED32 });
  add('public_key', 'public_key', { pkcs8: hostPkcs8 });
  add('public_key of a P-256 key', 'public_key', { pkcs8: p256Pkcs8 });
  add('key_info', 'key_info', { spki: hostSpki });
  add('key_info of a P-256 key', 'key_info', { spki: p256Spki });
  // Ed25519 is deterministic, so the signature itself is compared. P-256's ECDSA is deterministic in
  // the core (RFC 6979) and randomised in the Go port (measured: two signatures of one message are
  // equal from the Wasm and differ from Go), and an ECDSA signature is "to be verified, never
  // compared" (SPEC Appendix B's generator note), so the signature is described and `verify` below
  // proves each port accepts the other's.
  add('sign', 'sign', { pkcs8: hostPkcs8, data: b64url(new Uint8Array([1, 2, 3, 4])) });
  add('sign with a P-256 key', 'sign', { pkcs8: p256Pkcs8, data: b64url(new Uint8Array([1, 2, 3, 4])) }, (a) => (a?.sig ? { ...a, sig: '<an ECDSA signature>' } : a));
  // Made by the OTHER port, on purpose: this is the case that says each accepts the other's.
  add('verify a signature the other port made', 'verify', { spki: hostSpki, data: b64url(new Uint8Array([1, 2, 3, 4])), sig: f.go.call('sign', { pkcs8: hostPkcs8, data: b64url(new Uint8Array([1, 2, 3, 4])) }).sig });

  // C8 — RFC 8410: an Ed25519 AlgorithmIdentifier carries no parameters, in a private key either.
  const [pv, , pk] = derChildren(derRead(Buffer.from(hostPkcs8, 'base64url')));
  const oidOnly = derChildren(derChildren(derRead(Buffer.from(hostPkcs8, 'base64url')))[1])[0];
  const withNull = b64url(derSeq(pv.raw, derSeq(oidOnly.raw, derTlv(0x05, Buffer.alloc(0))), pk.raw));
  add('public_key from an Ed25519 PKCS #8 whose algorithm carries a NULL', 'public_key', { pkcs8: withNull });
  add('sign with an Ed25519 PKCS #8 whose algorithm carries a NULL', 'sign', { pkcs8: withNull, data: b64url(Buffer.from('x')) });
  // Half a UTF-16 surrogate pair in a string: JSON.stringify writes it as a \\u escape, which the
  // Rust core's parser refused in its own words and Go's read as U+FFFD. Both refuse it now, first,
  // in one answer (CONTRACT §0).
  add('verify with args holding a lone high surrogate', 'verify', { spki: 'a\ud800' });
  expect('verify with args holding a lone high surrogate', { error: 'bad_request', why: 'args: a string holds half of a UTF-16 surrogate pair' });

  // ── G: a key outside the profile is refused where it is read (R12, T2, T4) ───────────────────────
  //
  // The profile has two algorithms. A key of any other — RSA, P-384, a bare X25519 key, an Ed25519
  // key with a NULL after its OID — is `unsupported`, named by its OID, in both ports. A bare X25519
  // key was a third algorithm to both: `key_info` named `x25519`, which the contract's Alg does not
  // have, and `verify` answered `valid: false` where it refuses every other key it cannot read.
  for (const [kind, { spki, oid }] of Object.entries(f.foreign)) {
    const refused = { error: 'unsupported', why: `unsupported key type ${oid}` };
    add(`key_info of a key outside the profile: ${kind}`, 'key_info', { spki: b64url(spki) });
    expect(`key_info of a key outside the profile: ${kind}`, refused);
    add(`verify with a key outside the profile: ${kind}`, 'verify', { spki: b64url(spki), data: b64url(new Uint8Array(4)), sig: b64url(new Uint8Array(64)) });
    expect(`verify with a key outside the profile: ${kind}`, refused);
  }

  // An Ed25519 key of 32 bytes that decode to no point is no key (S4-1): the core refused it where it
  // read it, and the Go port read it as a key. y = 2 has no x on the curve. The control, y = 3, does.
  const ed25519Spki = (y) => b64url(Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from([y]), Buffer.alloc(31)]));
  add('key_info of an Ed25519 key that is not a point', 'key_info', { spki: ed25519Spki(2) });
  expect('key_info of an Ed25519 key that is not a point', { error: 'parse', why: 'Ed25519 key is not a point' });
  add('key_info of an Ed25519 key that is a point (the control)', 'key_info', { spki: ed25519Spki(3) });
  expect('key_info of an Ed25519 key that is a point (the control)', { alg: 'ed25519' });

  // ── C10: no whitespace is forgiven in an argument's base64url ────────────────────────────────────
  //
  // The contract forgives padding and the standard alphabet in an argument (§0), and nothing else
  // (js/b64url-arguments.json, which both ports' tests read). The core forgave every Unicode
  // whitespace character and the Go port four, so a key with a vertical tab in it was a key to the
  // Wasm and `parse` to the Go port. The control, the key as written, reads.
  const { hostPkcs8: heldPkcs8, hostSpki: heldSpki, hostFp } = f;
  const inside = (c) => heldPkcs8.slice(0, 8) + c + heldPkcs8.slice(8);
  for (const [what, c] of [
    ['a space', ' '], ['a tab', '\t'], ['CR LF', '\r\n'], ['a vertical tab', '\u000b'], ['a form feed', '\u000c'],
    ['a next line', '\u0085'], ['a no-break space', '\u00a0'], ['a line separator', '\u2028'],
  ]) {
    add(`public_key of a key with ${what} inside`, 'public_key', { pkcs8: inside(c) });
    expect(`public_key of a key with ${what} inside`, { error: 'parse', why: 'not base64url' });
  }
  add('public_key of the key as written (the control)', 'public_key', { pkcs8: heldPkcs8 });
  expect('public_key of the key as written (the control)', { alg: 'ed25519', spki: heldSpki, fingerprint: hostFp });
}
