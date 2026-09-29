// §6 of the contract: the vault — seal it, open it, and issue a leaf from what it holds.
import { seed, p256FromSeed, pkcs8Of, b64url, fingerprint } from '../../../pact-protocol/vectors/lib/keys.mjs';
import { buildRoot } from '../../../pact-protocol/vectors/lib/x509.mjs';
import { BORN } from '../cast.mjs';
import { RawArgs } from '../port.mjs';

const SALT = b64url(new Uint8Array(16).fill(3)), NONCE = b64url(new Uint8Array(12).fill(4));
const K = { m_kib: 8192, t: 1, p: 1 };

// The KDF's range, at BOTH ends and on BOTH paths. These parameters come out of an attacker-supplied
// document and are used before the passphrase is tested, and neither port bounded them the same way:
// Rust had no bounds at all (so `m_kib: 268435455` asked for ~256 GiB and `t: 4e9` never returned),
// Go bounded only the bottom at 8 and then let x/crypto quietly clamp the cost, and `name` was
// checked when opening but ignored when sealing. Every case below is a refusal both ports must word
// alike; the honest ones pin what a real caller asks for.
//
// Just over each line, not catastrophically over, and the reason is worth writing down: a case in
// this harness runs against an implementation that may have NO bound, and asking an unbounded
// Argon2id for 256 GiB or four billion passes hangs or kills the harness rather than testing it —
// which is what happened here on 2026-09-20. The boundary is what the ports must agree on; the
// catastrophic values are refused before any derivation and are asserted in the Rust unit tests.
// The MEMORY ceiling is deliberately not here: one KiB over it is still a 2 GiB allocation, which an
// unbounded implementation attempts. Both ports' unit tests assert it, where the bound exists and the
// refusal costs nothing.
const KDF_EDGES = [
  ['a KDF one pass over the ceiling', { name: 'argon2id', m_kib: 65536, t: 17, p: 1 }],
  ['a KDF below the floor', { name: 'argon2id', m_kib: 8, t: 1, p: 1 }],
  ['a KDF whose m_kib does not fit in 32 bits', { name: 'argon2id', m_kib: 4294967304, t: 3, p: 1 }],
  ['a KDF with no passes', { name: 'argon2id', m_kib: 65536, t: 0, p: 1 }],
  ['a KDF with too many lanes', { name: 'argon2id', m_kib: 65536, t: 3, p: 99 }],
  ['a KDF nobody implements', { name: 'scrypt', m_kib: 65536, t: 3, p: 1 }],
];

export default function vault({ add, expect }, f) {
  const { now, ENDPOINT, rootFp, csr, rootCsr, vault: held, record } = f;
  add('vault_seal', 'vault_seal', { passphrase: 'a passphrase', plaintext: { v: 2, roots: [] }, kdf: K, salt: SALT, nonce: NONCE });
  add('vault_seal of a record', 'vault_seal', { passphrase: 'a passphrase', plaintext: record, kdf: K, salt: SALT, nonce: NONCE });
  // An earlier generation is refused at both ends, in the same words, and nothing converts.
  add('vault_seal of an earlier generation', 'vault_seal', { passphrase: 'a passphrase', plaintext: { v: 1, roots: [], ledger: [], contacts: [] }, kdf: K, salt: SALT, nonce: NONCE });
  add('vault_seal of a plaintext with no generation', 'vault_seal', { passphrase: 'a passphrase', plaintext: { roots: [] }, kdf: K, salt: SALT, nonce: NONCE });
  // Port-built: the seed has no vault.
  const opened = { passphrase: 'a passphrase', vault: f.wasm.call('vault_seal', { passphrase: 'a passphrase', plaintext: { v: 2, roots: [] }, kdf: K, salt: SALT, nonce: NONCE }).vault };
  add('vault_open of what vault_seal made', 'vault_open', opened);
  // A KDF parameter is a whole number written as one. The same document with `t` spelled `1.0` has the
  // same canonical header, so it opened in the Go port, which read the number as a float, and was
  // refused by the core, which reads an integer; and `m_kib` 8192.5 was cut to 8192 there and then
  // failed as a wrong passphrase (C5). Raw text: JSON.stringify writes 1.0 as 1.
  for (const [what, from, to] of [
    ['t spelled 1.0', '"t":1,', '"t":1.0,'],
    ['m_kib spelled 8192.0', '"m_kib":8192,', '"m_kib":8192.0,'],
    ['p spelled 1e0', '"p":1}', '"p":1e0}'],
    ['m_kib 8192.5', '"m_kib":8192,', '"m_kib":8192.5,'],
  ]) {
    add(`vault_open of what vault_seal made, with ${what}`, 'vault_open', RawArgs.edit(opened, from, to));
    expect(`vault_open of what vault_seal made, with ${what}`, { error: 'vault', why: 'kdf parameters out of range' });
  }
  // A vault's document is written as a sealed plaintext is (canonical::in_order, Go inOrder): the core
  // sealed what serde_json wrote and the Go port the caller's text, so one document sealed under one
  // salt and nonce was two ciphertexts (a lead of the port-parity verification, 2026-09-30).
  for (const [what, text] of [
    ['a member written twice', '{"v":2,"roots":[],"x":1,"x":2}'],
    ['numbers and escapes JSON.stringify does not write', '{"v":2,"roots":[],"n":123456789012345678901234567890,"f":1.50,"e":1e2,"z":-0,"s":"\\u00e9\\/"}'],
  ]) {
    add(`vault_seal of a document holding ${what}`, 'vault_seal', RawArgs.edit({ passphrase: 'a passphrase', plaintext: '@@', kdf: K, salt: SALT, nonce: NONCE }, '"plaintext":"@@"', `"plaintext":${text}`));
  }
  add('vault_seal with a nonce that is not 12 bytes', 'vault_seal', { passphrase: 'a passphrase', plaintext: { v: 2 }, kdf: K, salt: SALT, nonce: b64url(new Uint8Array(8)) });
  add('vault_seal with an empty passphrase', 'vault_seal', { passphrase: '', plaintext: { v: 2 }, kdf: K });
  add('vault_seal with no plaintext', 'vault_seal', { passphrase: 'a passphrase', kdf: K });
  add('vault_open with a passphrase that is wrong', 'vault_open', { passphrase: 'wrong', vault: { format: 'pact-vault/1', kdf: { name: 'argon2id', ...K }, salt: b64url(new Uint8Array(16)), nonce: b64url(new Uint8Array(12)), ct: b64url(new Uint8Array(48)) } });
  add('vault_open of a document that is not a vault', 'vault_open', { passphrase: 'x', vault: { format: 'something-else' } });
  add('vault_open of no document at all', 'vault_open', { passphrase: 'x' });
  // C12 — the ranges at their edges, from contract/contract.json's `Kdf`, which a test in each port holds
  // its bounds to: the last value in, where it is cheap to derive with (t and p at the memory floor),
  // and the first value out. The memory ceiling's accepted side is 2 GiB and is not asked for here; its
  // refused side is the unit tests' (see the note on KDF_EDGES).
  const { m_kib: M, t: T, p: P } = f.defs.Kdf.properties;
  for (const [what, kdf, sealed] of [
    ['the most passes the contract allows', { name: 'argon2id', m_kib: M.minimum, t: T.maximum, p: 1 }, true],
    ['the most lanes the contract allows', { name: 'argon2id', m_kib: M.minimum, t: 1, p: P.maximum }, true],
    ['one lane more than the contract allows', { name: 'argon2id', m_kib: M.minimum, t: 1, p: P.maximum + 1 }, false],
    ['one KiB less than the contract allows', { name: 'argon2id', m_kib: M.minimum - 1, t: 1, p: 1 }, false],
  ]) {
    const args = { passphrase: 'a passphrase', plaintext: { v: 2 }, kdf, salt: SALT, nonce: NONCE };
    add(`vault_seal with ${what}`, 'vault_seal', args);
    if (sealed) add(`vault_open of what vault_seal made with ${what}`, 'vault_open', { passphrase: 'a passphrase', vault: f.wasm.call('vault_seal', args).vault });
    else expect(`vault_seal with ${what}`, { error: 'vault', why: 'kdf parameters out of range' });
  }
  for (const [what, kdf] of KDF_EDGES) {
    add(`vault_seal with ${what}`, 'vault_seal', { passphrase: 'a passphrase', plaintext: { v: 2 }, kdf, salt: SALT, nonce: NONCE });
    add(`vault_open of a document with ${what}`, 'vault_open', { passphrase: 'a passphrase', vault: { format: 'pact-vault/1', kdf, salt: SALT, nonce: NONCE, ct: b64url(new Uint8Array(32)) } });
  }
  add('wallet_issue', 'wallet_issue', { vault_plaintext: held, record_plaintext: record, root_fingerprint: rootFp, csr, now, valid_days: 365 }, f.withoutSerial('der'));
  // A vault that carries what belongs in the record, and a missing record: refused alike.
  add('wallet_issue from a vault that carries a ledger', 'wallet_issue', { vault_plaintext: { ...held, ledger: [], contacts: [] }, record_plaintext: record, root_fingerprint: rootFp, csr, now });
  add('wallet_issue without a record', 'wallet_issue', { vault_plaintext: held, root_fingerprint: rootFp, csr, now });
  add('wallet_issue for a root the vault does not hold', 'wallet_issue', { vault_plaintext: held, record_plaintext: record, root_fingerprint: 'sha256:' + 'A'.repeat(43), csr, now });
  add('wallet_issue of the root\'s own key', 'wallet_issue', { vault_plaintext: held, record_plaintext: record, root_fingerprint: rootFp, csr: rootCsr, now });
  // A request whose DER is one short SEQUENCE: csr_check's own `parse`, kept or not (TC-1, F18).
  add('wallet_issue of a request that is a truncated SEQUENCE', 'wallet_issue', { vault_plaintext: held, record_plaintext: record, root_fingerprint: rootFp, csr: b64url(new Uint8Array([0x30, 0x03, 0x02, 0x01])), now });
  const moved = { ...record, ledger: [{ root: rootFp, endpoint: 'https://elsewhere.example/mcp', not_before: '2026-09-10T00:00:00Z', not_after: '2027-09-10T00:00:00Z', issued_at: '2026-09-10T00:00:00Z' }] };
  add('wallet_issue for a second address', 'wallet_issue', { vault_plaintext: held, record_plaintext: moved, root_fingerprint: rootFp, csr, now });
  add('wallet_issue as a move', 'wallet_issue', { vault_plaintext: held, record_plaintext: moved, root_fingerprint: rootFp, csr, now, move: true }, f.withoutSerial('der'));
  add('wallet_issue with an empty vault', 'wallet_issue', { vault_plaintext: { v: 2, roots: [] }, record_plaintext: record, root_fingerprint: rootFp, csr, now });
  // SPEC §2.2, before any certificate is issued (TC-8's behaviour half): the root key is the root the
  // identity is known by; its certificate parses and is that key's; the key signs a challenge that
  // verifies under the certificate's key; and the chain assembled validates to the root at the
  // endpoint before it is returned. Both ports signed with whatever key sat beside the fingerprint,
  // and returned a leaf that failed chain rule 3 (measured, 2026-09-29).
  const rootEntry = held.roots[0];
  const heldWith = (o) => ({ ...held, roots: [{ ...rootEntry, ...o }] });
  const rootKeyedLeaf = f.alinaLeaf({ hostKey: f.rootKey, label: 'parity/root-keyed-leaf' });
  for (const [what, vault, want] of [
    ['a vault entry holding another key than its fingerprint names', heldWith({ pkcs8: f.p256Pkcs8 }), { error: 'bad_request', why: "the vault's root key is not the root it is filed under" }],
    ['a vault entry whose certificate is another root\'s', heldWith({ cert: f.p256RootDer }), { error: 'bad_request', why: "the vault's root certificate is not its key's" }],
    ['a vault entry whose certificate does not read', heldWith({ cert: 'AAAA' }), { error: 'parse' }],
    ['a vault entry whose certificate is its key\'s and is no root', heldWith({ cert: rootKeyedLeaf }), { error: 'bad_request', why: /^the chain it issued does not validate: chain rule \d: / }],
  ]) {
    add(`wallet_issue from ${what}`, 'wallet_issue', { vault_plaintext: vault, record_plaintext: record, root_fingerprint: rootFp, csr, now });
    expect(`wallet_issue from ${what}`, want);
  }

  // The review of PR #29 (C6, C8-C11, C18): every argument absent and of the wrong type, every document
  // shape the contract refuses, and every ledger entry that does not read — one answer from both ports.
  // A ledger entry that does not read is refused, never skipped: skipped, it could be the live leaf.
  add('vault_seal with no passphrase', 'vault_seal', { plaintext: { v: 2 }, kdf: K, salt: SALT, nonce: NONCE });
  add('vault_seal with a passphrase that is not a string', 'vault_seal', { passphrase: 5, plaintext: { v: 2 }, kdf: K, salt: SALT, nonce: NONCE });
  add('vault_seal of an earlier generation under a KDF out of range', 'vault_seal', { passphrase: 'a passphrase', plaintext: { v: 1 }, kdf: { name: 'argon2id', m_kib: 65536, t: 17, p: 1 }, salt: SALT, nonce: NONCE });
  add('vault_seal of a plaintext that is a string', 'vault_seal', { passphrase: 'a passphrase', plaintext: 'v2', kdf: K, salt: SALT, nonce: NONCE });
  const issueWith = (over) => ({ vault_plaintext: held, record_plaintext: record, root_fingerprint: rootFp, csr, now, ...over });
  const entry = moved.ledger[0];
  for (const [what, over] of [
    ['no root_fingerprint', { root_fingerprint: undefined }],
    ['a root_fingerprint that is not a string', { root_fingerprint: 5 }],
    ['no csr', { csr: undefined }],
    ['no now', { now: undefined }],
    ['a now that does not read', { now: 'yesterday' }],
    ['valid_days as a string', { valid_days: '30' }],
    ['valid_days of 0', { valid_days: 0 }],
    ['valid_days of 999', { valid_days: 999 }],
    ['a vault that is a string', { vault_plaintext: 'the vault' }],
    ['a vault of an earlier generation', { vault_plaintext: { ...held, v: 1 } }],
    ['a vault with a member it does not hold', { vault_plaintext: { ...held, note: 'hello' } }],
    ['a record that is a string', { record_plaintext: 'the record' }],
    ['a record that is a list', { record_plaintext: [] }],
    ['a record of an earlier generation', { record_plaintext: { ...record, v: 1 } }],
    ['a record with a member it does not hold', { record_plaintext: { ...record, note: 'hello' } }],
    ['a record whose ledger is not a list', { record_plaintext: { ...record, ledger: {} } }],
    ['a ledger entry with no endpoint', { record_plaintext: { ...record, ledger: [{ ...entry, endpoint: undefined }] } }],
    ['a ledger entry whose not_before does not read', { record_plaintext: { ...record, ledger: [{ ...entry, not_before: 'soon' }] } }],
    ['a ledger entry whose not_after does not read', { record_plaintext: { ...record, ledger: [{ ...entry, not_after: 'later' }] } }],
    ['a ledger entry whose root is not a string', { record_plaintext: { ...record, ledger: [{ ...entry, root: 5 }] } }],
    ['a ledger entry carrying the leaf', { record_plaintext: { ...record, ledger: [{ ...entry, leaf: 'MIIB' }] } }],
    ['a ledger entry that is not an object', { record_plaintext: { ...record, ledger: ['an entry'] } }],
    ['a ledger entry whose root is empty', { record_plaintext: { ...record, ledger: [{ ...entry, root: '' }] } }],
    ['a ledger entry whose endpoint is empty', { record_plaintext: { ...record, ledger: [{ ...entry, endpoint: '' }] } }],
    ['a root held on a card, which this function cannot sign with', { vault_plaintext: { ...held, roots: held.roots.map(({ pkcs8: _k, ...r }) => ({ ...r, holder: { kind: 'piv' } })) } }],
  ]) {
    const args = issueWith(over);
    for (const k of Object.keys(args)) if (args[k] === undefined) delete args[k];
    add(`wallet_issue with ${what}`, 'wallet_issue', args);
  }
  // An integer written with a fraction, and -0, which the core's reader takes for a float: neither is
  // a number of days. The Go port read -0 as 0 and refused it as out of range. Raw text: JSON.stringify
  // writes neither.
  for (const [what, to] of [['-0', '-0'], ['365.0', '365.0']]) {
    add(`wallet_issue with valid_days spelled ${what}`, 'wallet_issue', RawArgs.edit(issueWith({ valid_days: 365 }), '"valid_days":365', `"valid_days":${to}`));
    expect(`wallet_issue with valid_days spelled ${what}`, { error: 'bad_request', why: 'valid_days is required' });
  }
  // The control that must get through: a ledger that reads, an entry for another root, and an origin.
  add('wallet_issue over a ledger that reads', 'wallet_issue', issueWith({ valid_days: 30, record_plaintext: { ...record, ledger: [{ ...entry, root: 'sha256:' + 'B'.repeat(43), origin: 'https://app.example' }] } }), f.withoutSerial('der'));

  // Every member that is absent rather than empty.
  add('vault_seal with nothing to work from', 'vault_seal', { passphrase: 'a passphrase' });
  add('vault_open with nothing to work from', 'vault_open', { passphrase: 'x' });
  add('wallet_issue with nothing to work from', 'wallet_issue', {});

  // A request carrying a CARD-held sibling root's key. The request is port-built: the seed builds no
  // certificate signing request.
  const sibling = p256FromSeed(seed('parity/card-held-sibling'));
  const siblingDer = buildRoot({ cn: 'Alina at work', key: sibling, notBefore: BORN, label: 'parity/sibling' });
  const siblingCsr = f.wasm.call('csr_new', { cn: 'A Host', host_pkcs8: b64url(pkcs8Of(sibling.priv)), endpoint: ENDPOINT }).der;
  add('wallet_issue: a request carrying a CARD-held sibling root\'s key', 'wallet_issue', { vault_plaintext: { ...held, roots: [...held.roots, { fingerprint: fingerprint(sibling.pub), cn: 'Alina at work', cert: b64url(siblingDer), created: now, holder: { kind: 'piv' } }] }, record_plaintext: record, root_fingerprint: rootFp, csr: siblingCsr, now });

  // The review of PR #29 (C6): a ledger entry that does not read is REFUSED, and two ports that both
  // skipped it would agree with each other while one live leaf per identity failed open. So these carry
  // the answer SPEC §9 requires, and the control above ('over a ledger that reads') must issue.
  const unread = (m) => ({ error: 'bad_request', why: `the record's ledger entry 0 does not read${m ? `: ${m}` : ''}` });
  for (const [what, want] of [
    ['a ledger entry with no endpoint', unread('endpoint')],
    ['a ledger entry whose not_before does not read', unread('not_before')],
    ['a ledger entry whose not_after does not read', unread('not_after')],
    ['a ledger entry whose root is not a string', unread('root')],
    ['a ledger entry whose root is empty', unread('root')],
    ['a ledger entry whose endpoint is empty', unread('endpoint')],
    ['a ledger entry carrying the leaf', unread('leaf')],
    ['a ledger entry that is not an object', unread('')],
    ['a record whose ledger is not a list', { error: 'bad_request', why: "the record's ledger is a list" }],
    ['a root held on a card, which this function cannot sign with', { error: 'bad_request', why: 'this root is held on a card: wallet_issue signs only with a key the vault holds' }],
  ]) expect(`wallet_issue with ${what}`, want);
  expect('vault_seal of an earlier generation under a KDF out of range', { error: 'bad_request', why: 'a vault plaintext is v 2: the root, or the record' });
  // The contract's order: an empty passphrase is judged before a missing plaintext (T21). The core
  // named the plaintext first, and the Go port the passphrase.
  add('vault_seal with an empty passphrase and no plaintext', 'vault_seal', { passphrase: '', kdf: K });
  expect('vault_seal with an empty passphrase and no plaintext', { error: 'bad_request', why: 'empty passphrase' });

  // ── H: a vault's bytes are read strictly (C8) ────────────────────────────────────────────────────
  //
  // The Go port skipped a stray character in `ct` and opened a document the core refuses as damaged.
  // The tag covers the decoded bytes, so this was a second spelling of one document rather than a
  // forgery — and two readers that forgive different things disagree about which documents open. The
  // salt and the nonce are refused the same way. The control, `ct` padded, opens in both.
  const doc = opened.vault;
  const at5 = (text, c) => text.slice(0, 5) + c + text.slice(5);
  const damaged = { error: 'vault', why: 'the passphrase is wrong or the vault is damaged' };
  for (const [what, over, want] of [
    ['a ct with a stray character', { ct: at5(doc.ct, '.') }, damaged],
    ['a ct with a no-break space', { ct: at5(doc.ct, '\u00a0') }, damaged],
    ['a nonce with a stray character', { nonce: at5(doc.nonce, '!') }, damaged],
    ['a salt with a stray character', { salt: at5(doc.salt, '!') }, damaged],
    ['a ct padded (the control)', { ct: doc.ct + '='.repeat((4 - (doc.ct.length % 4)) % 4) }, { plaintext: { v: 2, roots: [] } }],
  ]) {
    add(`vault_open of what vault_seal made, with ${what}`, 'vault_open', { ...opened, vault: { ...doc, ...over } });
    expect(`vault_open of what vault_seal made, with ${what}`, want);
  }

  // ── I: one KDF reader, the salt floor, and the documents wallet_issue reads (S5) ──────────────────
  //
  // A caller's `kdf` and a document's are read by one reader in each port, never truncated. The Go port
  // read a caller's with encoding/json, before the passphrase and the plaintext, and answered `parse`
  // `kdf does not read` for a number of another type or spelling; the core read a `kdf` that was not an
  // object, or a `name` that was not a string, as the default, and sealed (R28, C4, F17). Hand-written:
  // the generator sends a string for `kdf` and nothing inside it.
  const range = { error: 'vault', why: 'kdf parameters out of range' };
  const unknown = { error: 'vault', why: 'unknown kdf' };
  const sealWith = (over) => ({ passphrase: 'a passphrase', plaintext: { v: 2 }, kdf: K, salt: SALT, nonce: NONCE, ...over });
  for (const [what, args, want] of [
    ['a kdf that is a number', sealWith({ kdf: 5 }), { error: 'bad_request', why: 'kdf is required' }],
    ['a kdf that is a list', sealWith({ kdf: [8192, 1, 1] }), { error: 'bad_request', why: 'kdf is required' }],
    ['a kdf that is a string, and no passphrase', { plaintext: { v: 2 }, kdf: 'x' }, { error: 'bad_request', why: 'passphrase is required' }],
    ['a kdf nobody implements, and an empty passphrase', sealWith({ passphrase: '', kdf: { name: 'scrypt' } }), { error: 'bad_request', why: 'empty passphrase' }],
    ['a kdf that is a string, and an earlier generation', sealWith({ plaintext: { v: 1 }, kdf: 'x' }), { error: 'bad_request', why: 'a vault plaintext is v 2: the root, or the record' }],
    ['a kdf whose name is a number', sealWith({ kdf: { ...K, name: 5 } }), unknown],
    ['a kdf whose m_kib is a string', sealWith({ kdf: { ...K, m_kib: '8192' } }), range],
    ['a kdf whose m_kib is negative', sealWith({ kdf: { ...K, m_kib: -1 } }), range],
    ['a kdf whose m_kib is 8192.5', sealWith({ kdf: { ...K, m_kib: 8192.5 } }), range],
    ['a kdf whose t is true', sealWith({ kdf: { ...K, t: true } }), range],
  ]) {
    add(`vault_seal with ${what}`, 'vault_seal', args);
    expect(`vault_seal with ${what}`, want);
  }
  // A whole number written as a fraction or an exponent, and -0: the core's reader takes each for a
  // float. Raw text: JSON.stringify writes none of them.
  for (const [what, from, to] of [
    ['t spelled 1.0', '"t":1,', '"t":1.0,'],
    ['m_kib spelled 8192.0', '"m_kib":8192,', '"m_kib":8192.0,'],
    ['p spelled 1e0', '"p":1}', '"p":1e0}'],
    ['t spelled -0', '"t":1,', '"t":-0,'],
  ]) {
    add(`vault_seal with a kdf whose ${what}`, 'vault_seal', RawArgs.edit(sealWith({}), from, to));
    expect(`vault_seal with a kdf whose ${what}`, range);
  }
  // Members by their exact names, and no others. encoding/json matched `M_KIB` to m_kib, so the Go port
  // refused 8 KiB as out of range, where the core read no `M_KIB` and sealed under the default. A null
  // member is left out: that case seals, and the two documents are compared whole (salt and nonce are
  // given).
  add('vault_seal with a kdf member named in capitals', 'vault_seal', sealWith({ kdf: { M_KIB: 8, t: 1, p: 1 } }));
  expect('vault_seal with a kdf member named in capitals', { error: 'vault', why: 'kdf holds name, m_kib, t and p, and nothing else: M_KIB' });
  add('vault_seal with a kdf whose name is null', 'vault_seal', sealWith({ kdf: { ...K, name: null } }));

  // The salt floor, in both ports' own words at both ends: the core passed Argon2id's (`salt is too
  // short`) and the Go port said `not a pact-vault/1 document` (R29, C6). The first salt out and the last
  // in, from contract/contract.json's VaultSaltMin; a nonce of the wrong length is judged first.
  const floor = f.defs.VaultSaltMin.const;
  const short = { error: 'vault', why: `salt is at least ${floor} bytes` };
  add('vault_seal with a salt one byte short', 'vault_seal', sealWith({ salt: b64url(new Uint8Array(floor - 1).fill(3)) }));
  expect('vault_seal with a salt one byte short', short);
  add('vault_seal with the shortest salt (the control)', 'vault_seal', sealWith({ salt: b64url(new Uint8Array(floor).fill(3)) }));
  add('vault_seal with a salt one byte short and a nonce of 8 bytes', 'vault_seal', sealWith({ salt: b64url(new Uint8Array(floor - 1)), nonce: b64url(new Uint8Array(8)) }));
  expect('vault_seal with a salt one byte short and a nonce of 8 bytes', { error: 'vault', why: 'nonce is 12 bytes' });
  add('vault_seal with an empty salt', 'vault_seal', sealWith({ salt: '' }));
  expect('vault_seal with an empty salt', short);

  // A document's header, read in its members' order by the one reader: a document that is not an
  // object was damage to the core and not a vault to the Go port; a `kdf` absent, null, not an object or
  // with no `name` opened in the core under the default and was unknown to the Go port; a parameter
  // absent was the default in the core and zero in the Go port (R30, T12, F17, C5).
  const withDoc = (over) => ({ passphrase: 'a passphrase', vault: { ...doc, ...over } });
  const withKdf = (over) => withDoc({ kdf: { ...doc.kdf, ...over } });
  const notVault = { error: 'vault', why: 'not a pact-vault/1 document' };
  const noKdf = { ...doc };
  delete noKdf.kdf;
  const { name: _name, ...nameless } = doc.kdf;
  const { m_kib: _m, ...memoryless } = doc.kdf;
  for (const [what, args, want] of [
    ['a vault that is a string', { passphrase: 'a passphrase', vault: 'x' }, notVault],
    ['a vault that is a list', { passphrase: 'a passphrase', vault: [] }, notVault],
    ['no passphrase', { vault: doc }, { error: 'bad_request', why: 'passphrase is required' }],
    ['no kdf', { passphrase: 'a passphrase', vault: noKdf }, unknown],
    ['a kdf that is null', withDoc({ kdf: null }), unknown],
    ['a kdf that is a string', withDoc({ kdf: 'argon2id' }), unknown],
    ['a kdf with no name', withDoc({ kdf: nameless }), unknown],
    ['a kdf whose name is a number', withKdf({ name: 5 }), unknown],
    ['a kdf with no m_kib', withDoc({ kdf: memoryless }), range],
    ['a kdf whose m_kib is null', withKdf({ m_kib: null }), range],
    ['a kdf whose t is 1.9', withKdf({ t: 1.9 }), range],
    ['a kdf whose p is 257', withKdf({ p: 257 }), range],
    ['a kdf whose m_kib is 2^32 + 8192', withKdf({ m_kib: 4294975488 }), range],
    ['a salt one byte short', withDoc({ salt: b64url(new Uint8Array(floor - 1).fill(3)) }), short],
    ['no salt', withDoc({ salt: undefined }), short],
    ['a salt that is a number', withDoc({ salt: 5 }), short],
    ['a salt one byte short and a nonce that is not base64url', withDoc({ salt: b64url(new Uint8Array(floor - 1)), nonce: '!!!' }), damaged],
    ['a salt one byte short and no nonce', withDoc({ salt: b64url(new Uint8Array(floor - 1)), nonce: undefined }), damaged],
  ]) {
    add(`vault_open of what vault_seal made, with ${what}`, 'vault_open', JSON.parse(JSON.stringify(args)));
    expect(`vault_open of what vault_seal made, with ${what}`, want);
  }

  // The documents wallet_issue reads, held to CONTRACT §6 in both ports, in the core's order and words
  // (F18, R31). The Go port decoded them into typed structs, so a member of the wrong type anywhere was
  // `arguments do not read` and a `pkcs8` of "" was a card-held root; the core read a wrong type as
  // absent or skipped it, and carried the rest. A root key that does not read is refused in its
  // reader's class, where the Go port said `bad_request` `the root key does not parse`.
  const [root0] = held.roots;
  const withRoot = (over) => issueWith({ vault_plaintext: { ...held, roots: [{ ...root0, ...over }] } });
  const rootUnread = (whose, m) => ({ error: 'bad_request', why: `the ${whose}'s root 0 does not read${m ? `: ${m}` : ''}` });
  const { created: _created, ...uncreated } = root0;
  for (const [what, args, want] of [
    ['a root key that is not base64url', withRoot({ pkcs8: '!!!' }), { error: 'parse', why: 'not base64url' }],
    ['a root key that is not a key', withRoot({ pkcs8: 'AAAA' }), { error: 'parse' }],
    ['a root key that is empty', withRoot({ pkcs8: '' }), { error: 'parse' }],
    ['a root key outside the profile', withRoot({ pkcs8: f.outside.Pkcs8 }), { error: 'unsupported', why: 'unsupported key type 1.3.101.112' }],
    ['a root key that is a number', withRoot({ pkcs8: 5 }), rootUnread('vault', 'pkcs8')],
    ['a root with no created', issueWith({ vault_plaintext: { ...held, roots: [uncreated] } }), rootUnread('vault', 'created')],
    ['a root whose created is a number', withRoot({ created: 5 }), rootUnread('vault', 'created')],
    ['a root whose cert is a number', withRoot({ cert: 5 }), rootUnread('vault', 'cert')],
    ['a root whose cn is a number', withRoot({ cn: 5 }), rootUnread('vault', 'cn')],
    ['a root whose fingerprint is not one', withRoot({ fingerprint: 'sha256:x' }), rootUnread('vault', 'fingerprint')],
    ['a root whose alg is not in the profile', withRoot({ alg: 'rsa' }), rootUnread('vault', 'alg')],
    ['a root whose holder is a string', withRoot({ holder: 'piv' }), rootUnread('vault', 'holder')],
    ['a root whose rebound_at is a string', withRoot({ rebound_at: 'x' }), rootUnread('vault', 'rebound_at')],
    ['a root with a member it does not hold', withRoot({ note: 'hello' }), rootUnread('vault', 'note')],
    ['a root that is not an object', issueWith({ vault_plaintext: { ...held, roots: ['a root'] } }), rootUnread('vault', '')],
    ['roots that are not a list', issueWith({ vault_plaintext: { ...held, roots: {} } }), { error: 'bad_request', why: "the vault's roots is a list" }],
    ['a vault with no roots', issueWith({ vault_plaintext: { v: 2 } }), { error: 'bad_request', why: "the vault's roots is a list" }],
    ['a prf that is a number', issueWith({ vault_plaintext: { ...held, prf: 5 } }), { error: 'bad_request', why: "the vault's prf does not read" }],
    ['a prf of 31 bytes', issueWith({ vault_plaintext: { ...held, prf: b64url(new Uint8Array(31)) } }), { error: 'bad_request', why: "the vault's prf does not read" }],
    ['a passkey with nothing in it', issueWith({ vault_plaintext: { ...held, passkey: {} } }), { error: 'bad_request', why: "the vault's passkey does not read" }],
    ['a record whose roots are not a list', issueWith({ record_plaintext: { ...record, roots: 'x' } }), { error: 'bad_request', why: "the record's roots is a list" }],
    ['a record whose root has no created', issueWith({ record_plaintext: { ...record, roots: [uncreated] } }), rootUnread('record', 'created')],
    ['a record whose contacts are a number', issueWith({ record_plaintext: { ...record, contacts: 5 } }), { error: 'bad_request', why: "the record's contacts is a list" }],
    ['a record whose contact is a number', issueWith({ record_plaintext: { ...record, contacts: [5] } }), { error: 'bad_request', why: "the record's contact 0 does not read" }],
    ['a record whose contact has no endpoint', issueWith({ record_plaintext: { ...record, contacts: [{ root: rootFp }] } }), { error: 'bad_request', why: "the record's contact 0 does not read: endpoint" }],
    ['a record whose contact was added at no instant', issueWith({ record_plaintext: { ...record, contacts: [{ root: rootFp, endpoint: ENDPOINT, added: 'yesterday' }] } }), { error: 'bad_request', why: "the record's contact 0 does not read: added" }],
    ['a record whose contact holds its state', issueWith({ record_plaintext: { ...record, contacts: [{ root: rootFp, endpoint: ENDPOINT, state: 'active' }] } }), { error: 'bad_request', why: "the record's contact 0 does not read: state" }],
    ['a record whose passkey is a string', issueWith({ record_plaintext: { ...record, passkey: 'x' } }), { error: 'bad_request', why: "the record's passkey does not read" }],
    ['a record whose backup_verified_at is negative', issueWith({ record_plaintext: { ...record, backup_verified_at: -1 } }), { error: 'bad_request', why: "the record's backup_verified_at does not read" }],
  ]) {
    add(`wallet_issue with ${what}`, 'wallet_issue', args);
    expect(`wallet_issue with ${what}`, want);
  }
  // The JSON literal null is absent inside the documents too (CONTRACT §0): wallet_issue's readers,
  // written when the documents were first held to their schemas (836d080), read a null member as one
  // of the wrong type in both ports — a root's pkcs8: null was `the vault's root 0 does not read:
  // pkcs8`, where before it was the absent key of a card-held root — while vault_seal's kdf reader
  // read null as absent (a lead of the port-parity verification, 2026-09-30). A null member each
  // document declares is absent now: an optional one is not there, a required one is named as a
  // missing one is. A member a document does not declare is refused whatever it holds, null too, as a
  // function's arguments are (a vault's ledger: null is still a vault carrying a ledger).
  {
    const nulled = (o, ...ms) => ({ ...o, ...Object.fromEntries(ms.map((m) => [m, null])) });
    const cardHeld = { error: 'bad_request', why: 'this root is held on a card: wallet_issue signs only with a key the vault holds' };
    for (const [what, args, want] of [
      ['a root whose pkcs8 is null', withRoot({ pkcs8: null }), cardHeld],
      ['a root whose fingerprint is null', withRoot({ fingerprint: null }), rootUnread('vault', 'fingerprint')],
      ['a vault whose roots are null', issueWith({ vault_plaintext: { ...held, roots: null } }), { error: 'bad_request', why: "the vault's roots is a list" }],
      ['a vault whose ledger is null', issueWith({ vault_plaintext: { ...held, ledger: null } }), { error: 'bad_request', why: 'a vault holds the root and nothing else: its ledger and contacts belong in the record' }],
      ['a vault with a null member it does not hold', issueWith({ vault_plaintext: { ...held, note: null } }), { error: 'bad_request', why: 'vault_plaintext holds v, roots, prf and passkey, and nothing else: note' }],
      ['a record whose contact has a null endpoint', issueWith({ record_plaintext: { ...record, contacts: [{ root: rootFp, endpoint: null }] } }), { error: 'bad_request', why: "the record's contact 0 does not read: endpoint" }],
      ['a record whose ledger entry has a null endpoint', issueWith({ record_plaintext: { ...record, ledger: [{ ...entry, endpoint: null }] } }), { error: 'bad_request', why: "the record's ledger entry 0 does not read: endpoint" }],
    ]) {
      add(`wallet_issue with ${what}`, 'wallet_issue', args);
      expect(`wallet_issue with ${what}`, want);
    }
    // The controls: every optional member null, in each document and in each entry, and the leaf is
    // issued as it is with none of them.
    add('wallet_issue from documents whose every optional member is null', 'wallet_issue', issueWith({
      valid_days: 30,
      vault_plaintext: { ...held, roots: [nulled(root0, 'alg', 'holder', 'rebound_at')], prf: null, passkey: null },
      record_plaintext: nulled({ ...record, roots: null, ledger: [{ ...entry, root: 'sha256:' + 'B'.repeat(43), origin: null }], contacts: [{ root: 'sha256:' + 'C'.repeat(43), endpoint: ENDPOINT, name: null, leaf: null, root_cert: null, added: null }] }, 'passkey', 'backup_verified_at'),
    }), f.withoutSerial('der'));
    expect('wallet_issue from documents whose every optional member is null', { endpoint: ENDPOINT, new_host: true });
    add('wallet_issue from a record whose ledger and contacts are null', 'wallet_issue', issueWith({ valid_days: 30, record_plaintext: { ...record, ledger: null, contacts: null } }), f.withoutSerial('der'));
    expect('wallet_issue from a record whose ledger and contacts are null', { new_host: true, warnings: ['new host: this endpoint\'s host has never been issued to'] });
  }
  // The control that must get through: every optional member present and read, and a record carrying
  // the root and a contact.
  add('wallet_issue from documents with every member they may hold', 'wallet_issue', issueWith({
    valid_days: 30,
    vault_plaintext: { ...held, roots: [{ ...root0, alg: 'ed25519', holder: { kind: 'piv' } }], prf: b64url(new Uint8Array(32).fill(7)), passkey: { credential_id: 'a-credential' } },
    record_plaintext: { ...record, roots: [{ ...uncreated, created: now, rebound_at: 1789214400000 }], contacts: [{ root: 'sha256:' + 'C'.repeat(43), endpoint: ENDPOINT, name: 'Bharat', added: now }], passkey: { credential_id: 'a-credential' }, backup_verified_at: 1789214400000 },
  }), f.withoutSerial('der'));
}
