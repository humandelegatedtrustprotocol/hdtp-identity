// Both ports, the same arguments, the same answers.
//
// The vectors prove that what the ports produce agrees on the bytes a peer sees. They say nothing
// about what a port answers when a caller gets it wrong, and nothing about the members of an answer
// the vectors do not carry — which is where the 2026-09-15 review found the two ports disagreeing:
// an explicit `valid_days: 0` was an error in one and a year in the other, `assemble_leaf` called a
// mismatched algorithm two different things, a non-object `args` two more, the root-key refusal was
// worded two ways, and `wallet_issue` answered three different shapes. CONTRACT §0 promises "the
// same names, the same shapes"; this is the test of that promise.
//
//   node js/parity.mjs            both ports, exits non-zero on any disagreement
import { makePort } from './port.mjs';
import { seed, ed25519FromSeed, pkcs8Of, b64url } from '../../pact-protocol/vectors/lib/keys.mjs';
import { buildRoot } from '../../pact-protocol/vectors/lib/x509.mjs';

const wasm = await makePort('wasm');
const go = await makePort('go');
if (!go) {
  console.log('the Go adapter is not built (go/bin/pact-identity-go): run `make build` in go/');
  process.exit(2);
}

// A root and a host key both ports can be handed.
const rootKey = ed25519FromSeed(seed('parity/root'));
const hostKey = ed25519FromSeed(seed('parity/host'));
const now = '2026-09-15T12:00:00Z';
const rootDer = b64url(buildRoot({ cn: 'Alina Rao', key: rootKey, notBefore: new Date('2026-09-01T00:00:00Z'), label: 'parity/root' }));
const rootPkcs8 = b64url(pkcs8Of(rootKey.priv));
const hostPkcs8 = b64url(pkcs8Of(hostKey.priv));
const csr = wasm.call('csr_new', { cn: 'Alina Rao', host_pkcs8: hostPkcs8, endpoint: 'https://agent.alina.example/mcp' }).der;
const rootCsr = wasm.call('csr_new', { cn: 'Alina Rao', host_pkcs8: rootPkcs8, endpoint: 'https://agent.alina.example/mcp' }).der;
const vault = { v: 1, roots: [{ fingerprint: wasm.call('parse_certificate', { der: rootDer }).fingerprint, cn: 'Alina Rao', pkcs8: rootPkcs8, cert: rootDer, created: now }], ledger: [], contacts: [] };
const rootFp = vault.roots[0].fingerprint;

// Each case: a name, the call, and which members of the answer must agree. `keys: '*'` compares the
// whole object; a list compares those members, so a case can ignore what is genuinely per-run
// (a random serial, a fresh signature) and still pin the shape.
const cases = [
  // ── a caller's mistakes: the same code and the same words from both ──────────────────────────
  ['unknown function', 'no_such_function', {}, '*'],
  ['args that are not an object', 'key_info', 'not-an-object', ['error']],
  ['a missing argument', 'key_info', {}, '*'],
  ['bytes that are not base64url', 'key_info', { spki: '!!!' }, ['error']],
  ['a root_spkis list that will not read', 'csr_check', { der: csr, root_spkis: [42] }, ['error']],
  ['the root-key refusal', 'csr_check', { der: rootCsr, root_spkis: [wasm.call('parse_certificate', { der: rootDer }).spki] }, '*'],
  ['an explicit valid_days of zero', 'issue_from_csr', { csr, root_cn: 'Alina Rao', root_pkcs8: rootPkcs8, now, valid_days: 0 }, ['error']],
  ['valid_days over 398', 'issue_from_csr', { csr, root_cn: 'Alina Rao', root_pkcs8: rootPkcs8, now, valid_days: 400 }, '*'],
  ['assemble_leaf with a sig_alg that is not the TBS\'s', 'assemble_leaf', { tbs: wasm.call('leaf_tbs', { cn: 'Alina Rao', root_cn: 'Alina Rao', root_spki: wasm.call('parse_certificate', { der: rootDer }).spki, host_spki: wasm.call('public_key', { pkcs8: hostPkcs8 }).spki, endpoint: 'https://agent.alina.example/mcp', not_before: now, not_after: '2027-09-01T00:00:00Z' }).tbs, sig: b64url(new Uint8Array(64)), sig_alg: b64url(new Uint8Array([0x30, 0x03, 0x06, 0x01, 0x2a])) }, ['error']],
  ['a chain of one', 'validate_chain', { chain: [rootDer], now }, '*'],
  ['a card that is not one', 'card_decode', { vcard: 'BEGIN:VCARD\r\nEND:VCARD\r\n', now }, '*'],
  ['an endpoint the guard refuses', 'address_guard', { endpoint: 'https://127.0.0.1/mcp', guest: false }, '*'],
  ['an empty passphrase', 'vault_seal', { passphrase: '', plaintext: { v: 1 }, kdf: { m_kib: 8192, t: 1, p: 1 } }, '*'],
  ['a vault a passphrase does not open', 'vault_open', { passphrase: 'wrong', vault: { format: 'pact-vault/1', kdf: { name: 'argon2id', m_kib: 8192, t: 1, p: 1 }, salt: b64url(new Uint8Array(16)), nonce: b64url(new Uint8Array(12)), ct: b64url(new Uint8Array(48)) } }, '*'],

  // ── answers whose shape the vectors do not carry ─────────────────────────────────────────────
  ['wallet_issue', 'wallet_issue', { vault_plaintext: vault, root_fingerprint: rootFp, csr, now, valid_days: 365 }, ['endpoint', 'not_before', 'not_after', 'new_host', 'warnings']],
  ['wallet_issue for a second address', 'wallet_issue', { vault_plaintext: { ...vault, ledger: [{ root: rootFp, leaf: '', endpoint: 'https://elsewhere.example/mcp', not_before: '2026-09-10T00:00:00Z', not_after: '2027-09-10T00:00:00Z', issued_at: '2026-09-10T00:00:00Z' }] }, root_fingerprint: rootFp, csr, now, valid_days: 365 }, ['error']],
  ['wallet_issue as a move', 'wallet_issue', { vault_plaintext: { ...vault, ledger: [{ root: rootFp, leaf: '', endpoint: 'https://elsewhere.example/mcp', not_before: '2026-09-10T00:00:00Z', not_after: '2027-09-10T00:00:00Z', issued_at: '2026-09-10T00:00:00Z' }] }, root_fingerprint: rootFp, csr, now, valid_days: 365, move: true }, ['endpoint', 'new_host', 'warnings']],
  ['a card with a name outside ASCII folds alike', 'card_encode', { fn: 'é'.repeat(80), cert: rootDer, seal: 'required' }, '*'],
  ['a card whose name straddles the fold', 'card_encode', { fn: 'a'.repeat(70) + 'ü'.repeat(10), cert: rootDer }, '*'],
  ['is_normal_https on a port', 'is_normal_https', { url: 'https://agent.alina.example:8443/mcp' }, '*'],
  ['parse_certificate', 'parse_certificate', { der: rootDer }, '*'],
];

// Members are compared by name, not by the order a language's JSON encoder happens to emit them in
// (Go sorts a map's keys; serde keeps insertion order). Order is not part of the contract.
const canonical = (v) => {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])]));
  return v;
};
const pick = (o, keys) => canonical(keys === '*' ? o : Object.fromEntries(keys.map((k) => [k, o?.[k]])));
const answer = (port, fn, args) => {
  try { return port.call(fn, args); } catch (e) { return { threw: String(e.message || e) }; }
};

let bad = 0;
for (const [name, fn, args, keys] of cases) {
  const a = pick(answer(wasm, fn, args), keys);
  const b = pick(answer(go, fn, args), keys);
  const same = JSON.stringify(a) === JSON.stringify(b);
  if (!same) bad++;
  console.log(`  ${same ? 'agree  ' : 'DIFFER '} ${name}`);
  if (!same) {
    console.log(`    wasm ${JSON.stringify(a)}`);
    console.log(`    go   ${JSON.stringify(b)}`);
  }
}
console.log(`\n${cases.length - bad}/${cases.length} boundary answers agree between the ports`);
process.exit(bad ? 1 : 0);
