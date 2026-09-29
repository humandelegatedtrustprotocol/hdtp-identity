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
  add('wallet_issue: a request carrying a CARD-held sibling root\'s key', 'wallet_issue', { vault_plaintext: { ...held, roots: [...held.roots, { fingerprint: fingerprint(sibling.pub), cn: 'Alina at work', cert: b64url(siblingDer), holder: { kind: 'piv' } }] }, record_plaintext: record, root_fingerprint: rootFp, csr: siblingCsr, now });

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
}
