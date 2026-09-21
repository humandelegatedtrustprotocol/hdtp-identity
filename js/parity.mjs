// Both ports, the same arguments, the same answers — as a gate, not a courtesy.
//
// The vectors prove that what the ports produce agrees on the bytes a peer sees. They say nothing
// about what a port answers when a caller gets it wrong, and nothing about the members of an answer
// the vectors do not carry. That is where every cross-port defect has been found:
//
//   2026-09-15, internal: `valid_days: 0` was an error in one port and a year in the other;
//     `assemble_leaf` called a mismatched algorithm two different things; `wallet_issue` answered
//     three different shapes; the root-key refusal was worded two ways.
//   2026-09-15, ultra: the Go address guard compared an authority carrying a port against a bare
//     host, so `https://127.0.0.1:8443/mcp` passed where the Rust core refused it; and Go's
//     base64url decoder skipped illegal characters instead of failing, so a malformed `root_spkis`
//     read as "no roots to refuse against" and §9's root-key refusal failed open.
//
// Both of those were reachable from the boundary with one hostile argument, and neither test suite
// could see them: each port's tests only ever ask its own port. This file asks both.
//
//   node js/parity.mjs            exits non-zero on any disagreement, or on an unguarded function
//
// It also fails when the contract's surface grows without a case here, so the harness cannot fall
// silently behind the thing it guards.
import { makePort } from './port.mjs';
import { seed, ed25519FromSeed, p256FromSeed, x25519FromSeed, pkcs8Of, b64url } from '../../pact-protocol/vectors/lib/keys.mjs';
import { buildRoot, buildLeaf } from '../../pact-protocol/vectors/lib/x509.mjs';
import { ecdsaTwin, ecdsaIsLowS, read as derRead, children as derChildren, tlv as derTlv, seq as derSeq, set as derSet, bitstr as derBitstr, int as derInt } from '../../pact-protocol/vectors/lib/der.mjs';
import { signDetached } from '../../pact-protocol/vectors/lib/hpke.mjs';

const wasm = await makePort('wasm');
const go = await makePort('go');
if (!go) {
  console.log('the Go adapter is not built (go/bin/pact-identity-go): run `make build` in go/');
  process.exit(2);
}

// ── material both ports can be handed ──────────────────────────────────────────────────────────
const rootKey = ed25519FromSeed(seed('parity/root'));
const hostKey = ed25519FromSeed(seed('parity/host'));
const p256Key = p256FromSeed(seed('parity/p256'));
const now = '2026-09-15T12:00:00Z';
const ENDPOINT = 'https://agent.alina.example/mcp';
const rootDer = b64url(buildRoot({ cn: 'Alina Rao', key: rootKey, notBefore: new Date('2026-09-01T00:00:00Z'), label: 'parity/root' }));
const leafDer = b64url(buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: ENDPOINT, notBefore: new Date('2026-09-01T00:00:00Z'), notAfter: new Date('2027-09-01T00:00:00Z'), label: 'parity/leaf' }));
const rootPkcs8 = b64url(pkcs8Of(rootKey.priv));
const hostPkcs8 = b64url(pkcs8Of(hostKey.priv));
const p256Pkcs8 = b64url(pkcs8Of(p256Key.priv));
const rootSpki = wasm.call('parse_certificate', { der: rootDer }).spki;
const hostSpki = wasm.call('public_key', { pkcs8: hostPkcs8 }).spki;
const rootFp = wasm.call('parse_certificate', { der: rootDer }).fingerprint;
const csr = wasm.call('csr_new', { cn: 'Alina Rao', host_pkcs8: hostPkcs8, endpoint: ENDPOINT }).der;
const rootCsr = wasm.call('csr_new', { cn: 'Alina Rao', host_pkcs8: rootPkcs8, endpoint: ENDPOINT }).der;
const card = wasm.call('card_encode', { fn: 'Alina Rao', cert: leafDer, seal: 'required' }).vcard;
const vault = { v: 1, roots: [{ fingerprint: rootFp, cn: 'Alina Rao', pkcs8: rootPkcs8, cert: rootDer, created: now }], ledger: [], contacts: [] };
const leafTbs = wasm.call('leaf_tbs', { cn: 'Alina Rao', root_cn: 'Alina Rao', root_spki: rootSpki, host_spki: hostSpki, endpoint: ENDPOINT, not_before: now, not_after: '2027-09-01T00:00:00Z' });
const sealed = wasm.call('seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: { name: 'send_message' }, msg_id: 'p-1', ts: Math.floor(Date.parse(now) / 1000) });
const sealedNoTool = wasm.call('seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: {}, msg_id: 'p-1', ts: Math.floor(Date.parse(now) / 1000) });
const node = {
  endpoint: ENDPOINT,
  accept_new_hosts: 'auto',
  chain: [leafDer, rootDer],
  keys: [{ kid: wasm.call('key_info', { spki: hostSpki }).fingerprint, leaf: leafDer, pkcs8: hostPkcs8, current: true }],
  former: [], sibling_kids: [], pins: [], tombstones: [], former_endpoints: [], seen: [],
};

// ── the adversarial table ──────────────────────────────────────────────────────────────────────
//
// How a case is compared. `'*'` compares the whole answer and is the default, because a member that
// nobody thought to name is exactly the member that goes missing. Where an answer carries something
// genuinely per-run — a random serial, a fresh ephemeral — the case passes a FUNCTION that replaces
// that one value with a description of it, and everything else is still compared. A plain key list
// is the weakest form and is used only where neither is possible; the gate below counts how many
// functions are compared whole, so weakening a case is visible rather than quiet.
//
// Nothing here may narrow to `['error']` merely to make a disagreement go away: a differing `why` IS
// the finding.

// `shape` keeps the member's presence and size and drops its value, for something drawn fresh.
const shape = (v) => (typeof v === 'string' ? `<${v.length} chars>` : v === undefined ? undefined : `<${typeof v}>`);
// `certShape` replaces a base64url certificate or TBS with its parsed form minus the random serial,
// so everything the profile fixes is still compared byte for byte.
const parsedMinusSerial = (port, b64) => {
  const c = port.call('parse_certificate', { der: b64 });
  if (c.error) return c;
  const { serial, sig_alg: _s, fingerprint, ...rest } = c;
  return { ...rest, serial: serial ? '<a serial>' : serial }; // its length moves with its leading byte
};
const withoutSerial = (member) => (answer, port) => {
  if (!answer?.[member]) return answer;
  const out = { ...answer, [member]: parsedMinusSerial(port, answer[member]) };
  // A serial of 8 bytes may encode in 8 or 9, so the certificate's length moves with it.
  if (out[member]?.bytes) out[member] = { ...out[member], bytes: '<a serial\'s worth>' };
  if (out.ledger_entry?.leaf) out.ledger_entry = { ...out.ledger_entry, leaf: parsedMinusSerial(port, out.ledger_entry.leaf) };
  if (out.ledger_entry?.leaf?.bytes) out.ledger_entry.leaf = { ...out.ledger_entry.leaf, bytes: '<a serial\'s worth>' };
  return out;
};
const B64_BAD = ['!!!', '', 'AA=', 'a b c', '~~~~'];
const LOCAL = [
  // 255.255.255.255 is the one spelling of "not a real peer" that netip has no predicate for, so the
  // Go guard admitted it while Rust's `is_broadcast` refused: a stranger's card could name the IPv4
  // broadcast address and the node would pin it.
  'https://255.255.255.255/mcp',
  'https://127.0.0.1/mcp', 'https://127.0.0.1:8443/mcp', 'https://localhost/mcp', 'https://localhost:8443/mcp',
  'https://[::1]/mcp', 'https://[::1]:8443/mcp', 'https://10.0.0.5:8443/mcp', 'https://192.168.1.1:443/mcp',
  'https://169.254.169.254/mcp', 'https://100.64.0.1:9000/mcp', 'https://0.0.0.0/mcp', 'https://[fe80::1]:9999/mcp',
  'https://[fd00::1]/mcp', 'https://[::ffff:10.0.0.1]/mcp', 'https://api.localhost/mcp', 'https://localhost./mcp',
  'https://127.1/mcp', 'https://2130706433/mcp', 'https://0x7f000001/mcp', 'https://0177.0.0.1/mcp',
];
const URLS = [
  ENDPOINT, 'https://agent.alina.example:8443/mcp', 'https://agent.alina.example:443/mcp', 'https://agent.alina.example/mcp/',
  'https://agent.alina.example/', 'https://agent.alina.example', 'http://agent.alina.example/mcp',
  'https://AGENT.alina.example/mcp', 'https://user@agent.alina.example/mcp', 'https://agent.alina.example/mcp?q=1',
  'https://agent.alina.example/mcp#f', 'https://agent.alina.example/./mcp', 'https://agent.alina.example/a/../mcp',
  'https://agent.alina.example/%2f', 'https://agent.alina.example/%41', 'https://agent.alina.example/a b',
  'https://agent.alina.example:0/mcp', 'https://agent.alina.example:99999/mcp', 'https://agent.alina.example:08443/mcp',
  'https://[2001:db8::1]:8443/mcp', 'https://[2001:db8::1]8443/mcp', '', 'not a url', 'https://',
];

const cases = [];
const add = (name, fn, args, how = '*') => cases.push([name, fn, args, how]);

// the dispatcher itself
add('a function nobody defines', 'no_such_function', {});
add('args that are not an object', 'key_info', 'not-an-object');
add('args that are a list', 'key_info', [1, 2]);
add('args that are null', 'key_info', null);

// §1 keys
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
add('public_key of a key that is not one', 'public_key', { pkcs8: b64url(new Uint8Array(16)) });
add('public_key with no argument', 'public_key', {});
add('key_info of an spki that is not one', 'key_info', { spki: b64url(new Uint8Array(4)) });
add('key_info with no argument', 'key_info', {});
for (const bad of B64_BAD) add(`key_info of bytes that are not base64url (${JSON.stringify(bad)})`, 'key_info', { spki: bad });
add('key_info of a number', 'key_info', { spki: 123 });
add('sign with a public key', 'sign', { pkcs8: hostSpki, data: b64url(new Uint8Array(4)) });
add('sign with no data', 'sign', { pkcs8: hostPkcs8 });
add('verify a signature that is not one', 'verify', { spki: hostSpki, data: b64url(new Uint8Array(4)), sig: b64url(new Uint8Array(4)) });
add('verify with an empty signature', 'verify', { spki: hostSpki, data: b64url(new Uint8Array(4)), sig: '' });
add('suite_for an spki that is not one', 'suite_for', { spki: b64url(new Uint8Array(4)) });

// §2 certificates
add('parse_certificate of a root', 'parse_certificate', { der: rootDer });
add('parse_certificate of a leaf', 'parse_certificate', { der: leafDer });
add('parse_certificate of nothing', 'parse_certificate', { der: '' });
add('parse_certificate of a truncated certificate', 'parse_certificate', { der: rootDer.slice(0, 40) });
add('parse_certificate of bytes that are not DER', 'parse_certificate', { der: b64url(new Uint8Array([1, 2, 3, 4])) });
add('profile_error of a leaf read as a root', 'profile_error', { der: leafDer, kind: 'root' });
add('profile_error of a root read as a leaf', 'profile_error', { der: rootDer, kind: 'leaf' });
add('profile_error with a kind nobody has', 'profile_error', { der: rootDer, kind: 'middle' });
// A serial is random when it is not given, so every case that builds one gives one: the answer is
// then byte-for-byte comparable, which is a stronger assertion than narrowing the keys would be.
const SERIAL = b64url(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
add('build_root with no key', 'build_root', { cn: 'Alina Rao', not_before: now, serial: SERIAL });
add('build_root', 'build_root', { cn: 'Alina Rao', pkcs8: rootPkcs8, not_before: now, serial: SERIAL });
add('root_tbs', 'root_tbs', { cn: 'Alina Rao', spki: rootSpki, not_before: now, serial: SERIAL });
add('root_tbs with no key', 'root_tbs', { cn: 'Alina Rao', not_before: now, serial: SERIAL });
add('root_tbs with a serial that is too long', 'root_tbs', { cn: 'A', spki: rootSpki, not_before: now, serial: b64url(new Uint8Array(21)) });
add('leaf_tbs', 'leaf_tbs', { cn: 'Alina Rao', root_cn: 'Alina Rao', root_spki: rootSpki, host_spki: hostSpki, endpoint: ENDPOINT, not_before: now, not_after: '2027-09-01T00:00:00Z', serial: SERIAL });
add('leaf_tbs with no issuer', 'leaf_tbs', { cn: 'A', root_cn: 'A', host_spki: hostSpki, endpoint: ENDPOINT, not_before: now, not_after: '2027-09-01T00:00:00Z' });
add('build_leaf', 'build_leaf', { cn: 'Alina Rao', root_cn: 'Alina Rao', root_pkcs8: rootPkcs8, host_spki: hostSpki, endpoint: ENDPOINT, not_before: now, not_after: '2027-09-01T00:00:00Z', serial: SERIAL });
add('build_root with a serial that is too short', 'build_root', { cn: 'Alina Rao', pkcs8: rootPkcs8, not_before: now, serial: b64url(new Uint8Array(4)) });
add('build_root with an instant that is not one', 'build_root', { cn: 'Alina Rao', pkcs8: rootPkcs8, not_before: 'yesterday', serial: SERIAL });
add('build_leaf over 398 days', 'build_leaf', { cn: 'A', root_cn: 'A', root_pkcs8: rootPkcs8, host_spki: hostSpki, endpoint: ENDPOINT, not_before: '2026-09-01T00:00:00Z', not_after: '2027-11-01T00:00:00Z', serial: SERIAL });
add('build_leaf backwards in time', 'build_leaf', { cn: 'A', root_cn: 'A', root_pkcs8: rootPkcs8, host_spki: hostSpki, endpoint: ENDPOINT, not_before: '2027-09-01T00:00:00Z', not_after: '2026-09-01T00:00:00Z', serial: SERIAL });
for (const url of ['https://127.0.0.1/mcp', 'http://a.example/x', 'https://a.example/x/'])
  add(`build_leaf naming ${url}`, 'build_leaf', { cn: 'A', root_cn: 'A', root_pkcs8: rootPkcs8, host_spki: hostSpki, endpoint: url, not_before: now, not_after: '2027-09-01T00:00:00Z', serial: SERIAL });
// The HAPPY PATH first, and it was missing: all fourteen cases below are refusals, so until the
// `provenWhole` gate learned to read `ok: false` (2026-09-20) the six chain rules had never had a
// SUCCESSFUL answer compared between the ports. `leaf_spki`, `leaf_fingerprint`, `root_fingerprint`
// and `endpoint` are what a caller pins on, and a member dropped from any of them was invisible.
add('validate_chain of a real chain', 'validate_chain', { chain: [leafDer, rootDer], now });
add('validate_chain against the root and endpoint it really has', 'validate_chain', { chain: [leafDer, rootDer], now, expected_root: rootFp, expected_endpoint: ENDPOINT });
// ── SPEC 2.1.1: the three rules added to the profile on 2026-09-20, held across the ports ─────────
//
// A P-256-rooted identity, because the first rule is about ECDSA and every other fixture here is
// Ed25519 — which is how a port could have lacked the rule entirely with this harness green.
const p256RootDer = b64url(buildRoot({ cn: 'Bharat Mehta', key: p256Key, notBefore: new Date('2026-09-01T00:00:00Z'), label: 'parity/p256root' }));
const p256Leaf = (misencode = {}) => b64url(buildLeaf({ cn: 'Bharat Mehta', rootCn: 'Bharat Mehta', root: p256Key, hostKey, endpoint: ENDPOINT, notBefore: new Date('2026-09-01T00:00:00Z'), notAfter: new Date('2027-09-01T00:00:00Z'), label: 'parity/p256leaf', misencode }));
const twinLeaf = p256Leaf({ sigTwin: true });
add('validate_chain of a P-256 chain', 'validate_chain', { chain: [p256Leaf(), p256RootDer], now });
add('validate_chain of a leaf whose ECDSA signature is the high twin', 'validate_chain', { chain: [twinLeaf, p256RootDer], now });
add('parse_certificate of that leaf', 'parse_certificate', { der: twinLeaf }, (a) => ({ profile_error: a.profile_error, kind: a.kind }));
add('profile_error of that leaf', 'profile_error', { der: twinLeaf, kind: 'leaf' });
add('card_decode of a card carrying that leaf', 'card_decode', { vcard: wasm.call('card_encode', { fn: 'Bharat Mehta', cert: twinLeaf }).vcard, now });
// The external-signing seam normalises: a token's high-S signature goes in, the low-S certificate
// comes out, and it is the SAME certificate from both ports.
{
  const plan = wasm.call('leaf_tbs', { cn: 'Bharat Mehta', root_cn: 'Bharat Mehta', root_spki: wasm.call('public_key', { pkcs8: p256Pkcs8 }).spki, host_spki: hostSpki, endpoint: ENDPOINT, not_before: now, not_after: '2027-09-01T00:00:00Z', serial: b64url(new Uint8Array(8).fill(0x51)) });
  const low = signDetached(p256Key.priv, Buffer.from(plan.tbs, 'base64url'));
  const high = ecdsaTwin(low);
  if (ecdsaIsLowS(high)) throw new Error('parity: the fixture meant to be the HIGH twin is not');
  const lowS = (answer) => { if (!answer.der) return answer; const cert = derChildren(derRead(Buffer.from(answer.der, 'base64url'))); return { ...answer, low_s: ecdsaIsLowS(cert[2].content.subarray(1)) }; };
  add('assemble_leaf with a token\'s high-S signature', 'assemble_leaf', { tbs: plan.tbs, sig: b64url(high), sig_alg: plan.sig_alg }, lowS);
  add('assemble_leaf with a low-S signature', 'assemble_leaf', { tbs: plan.tbs, sig: b64url(low), sig_alg: plan.sig_alg }, lowS);
}
// An extension VALUE under another type, and a basicConstraints that reads two ways (2026-09-20).
// Every one of these validated as a chain in BOTH ports; the refusal has to be the same words in each.
{
  const strictLeaf = (misencode) => b64url(buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: ENDPOINT, notBefore: new Date('2026-09-01T00:00:00Z'), notAfter: new Date('2027-09-01T00:00:00Z'), label: 'parity/strict', misencode }));
  for (const [what, misencode] of [
    ['a keyUsage that is an OCTET STRING', { retag: { oid: '2.5.29.15', tag: 0x04 } }],
    ['a subjectKeyIdentifier that is a BIT STRING', { retag: { oid: '2.5.29.14', tag: 0x03 } }],
    ['a subjectAltName that is a SET', { retag: { oid: '2.5.29.17', tag: 0x31 } }],
    ['an authorityKeyIdentifier that is an OCTET STRING', { retag: { oid: '2.5.29.35', tag: 0x04 } }],
    ['a basicConstraints holding a NULL', { basicConstraints: '30020500' }],
    ['a basicConstraints holding only an INTEGER', { basicConstraints: '3003020100' }],
  ]) {
    add(`validate_chain of a leaf with ${what}`, 'validate_chain', { chain: [strictLeaf(misencode), rootDer], now });
    add(`parse_certificate of a leaf with ${what}`, 'parse_certificate', { der: strictLeaf(misencode) });
  }
  for (const [what, bc] of [['TRUE, 5, 0', '30090101ff020105020100'], ['a pathLenConstraint of 128', '30070101ff02020080']]) {
    const root = b64url(buildRoot({ cn: 'Alina Rao', key: rootKey, notBefore: new Date('2026-09-01T00:00:00Z'), label: 'parity/root', basicConstraints: bc }));
    add(`validate_chain under a root whose basicConstraints is ${what}`, 'validate_chain', { chain: [leafDer, root], now });
    add(`parse_certificate of a root whose basicConstraints is ${what}`, 'parse_certificate', { der: root });
  }
}
// A validity field that is not a date, which one port used to read as 2 March.
add('validate_chain of a leaf dated 30 February', 'validate_chain', { chain: [b64url(buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: ENDPOINT, notBefore: new Date('2026-03-02T12:00:00Z'), notAfter: new Date('2027-03-01T00:00:00Z'), label: 'parity/feb30', misencode: { notBefore: '260230120000Z' } })), rootDer], now });
// An extension whose OID has an arc over 128 bits: 2.5.29.(2^128 + 17). One port accumulated arcs in
// a u128 and read this as 2.5.29.17 — subjectAltName — and parsed it as one.
add('parse_certificate of a leaf with a 129-bit OID arc', 'parse_certificate', { der: b64url(buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: ENDPOINT, notBefore: new Date('2026-09-01T00:00:00Z'), notAfter: new Date('2027-09-01T00:00:00Z'), label: 'parity/bigoid', extra: [{ oid: '2.5.29.' + (2n ** 128n + 17n).toString(), critical: false, value: Buffer.from([0x30, 0x00]) }] })) });
add('validate_chain of a chain of one', 'validate_chain', { chain: [rootDer], now });
add('validate_chain of a chain of three', 'validate_chain', { chain: [leafDer, rootDer, rootDer], now });
add('validate_chain of an empty chain', 'validate_chain', { chain: [], now });
add('validate_chain with no chain at all', 'validate_chain', { now });
add('validate_chain of leaf and leaf', 'validate_chain', { chain: [leafDer, leafDer], now });
add('validate_chain of root and root', 'validate_chain', { chain: [rootDer, rootDer], now });
add('validate_chain the wrong way round', 'validate_chain', { chain: [rootDer, leafDer], now });
add('validate_chain against the wrong root', 'validate_chain', { chain: [leafDer, rootDer], now, expected_root: 'sha256:' + 'A'.repeat(43) });
add('validate_chain against another endpoint', 'validate_chain', { chain: [leafDer, rootDer], now, expected_endpoint: 'https://elsewhere.example/mcp' });
add('validate_chain before the leaf begins', 'validate_chain', { chain: [leafDer, rootDer], now: '2026-08-01T00:00:00Z' });
add('validate_chain after the leaf ends', 'validate_chain', { chain: [leafDer, rootDer], now: '2028-01-01T00:00:00Z' });
add('validate_chain with an instant that is not one', 'validate_chain', { chain: [leafDer, rootDer], now: 'soon' });
add('validate_chain of members that are not base64url', 'validate_chain', { chain: ['!!!', '!!!'], now });
add('validate_chain of members that are not strings', 'validate_chain', { chain: [42, 43], now });
add('compare_leaves with itself', 'compare_leaves', { pinned: leafDer, presented: leafDer });
add('compare_leaves against a root', 'compare_leaves', { pinned: leafDer, presented: rootDer });
add('compare_leaves of nothing', 'compare_leaves', { pinned: '', presented: '' });
for (const url of URLS) add(`is_normal_https ${JSON.stringify(url)}`, 'is_normal_https', { url });
add('is_normal_https with no url', 'is_normal_https', {});
for (const endpoint of LOCAL) add(`address_guard ${endpoint}`, 'address_guard', { endpoint, guest: true });
for (const endpoint of [ENDPOINT, 'https://agent.alina.example:8443/mcp', 'https://203.0.113.9:8443/mcp'])
  add(`address_guard allows ${endpoint}`, 'address_guard', { endpoint, guest: true });
add('address_guard on a guest naming us', 'address_guard', { endpoint: ENDPOINT, self_endpoint: ENDPOINT, guest: true });
add('address_guard on a contact naming us', 'address_guard', { endpoint: ENDPOINT, self_endpoint: ENDPOINT, guest: false });
add('address_guard with no endpoint', 'address_guard', { guest: true });
for (const ip of ['10.0.0.1', '8.8.8.8', '::1', '[::1]', 'not-an-ip', '', '0177.0.0.1', '::ffff:10.0.0.1', '100.64.0.1', '224.0.0.1', '255.255.255.255'])
  add(`ip_is_private ${JSON.stringify(ip)}`, 'ip_is_private', { ip });

// §3 certificate signing requests
add('csr_new with no key', 'csr_new', { cn: 'A', endpoint: ENDPOINT });
add('csr_new naming a local address', 'csr_new', { cn: 'A', host_pkcs8: hostPkcs8, endpoint: 'https://127.0.0.1:8443/mcp' });
add('csr_new naming nothing', 'csr_new', { cn: 'A', host_pkcs8: hostPkcs8, endpoint: '' });
add('csr_new with a dns_name that is not the host', 'csr_new', { cn: 'A', host_pkcs8: hostPkcs8, endpoint: ENDPOINT, dns_name: 'elsewhere.example' });
add('csr_check of bytes that are not a request', 'csr_check', { der: b64url(new Uint8Array([1, 2, 3])) });
add('csr_check of a certificate', 'csr_check', { der: rootDer });
add('csr_check with no request', 'csr_check', {});
add('the root-key refusal', 'csr_check', { der: rootCsr, root_spkis: [rootSpki] });
add('the root-key refusal with a list that will not read', 'csr_check', { der: rootCsr, root_spkis: ['!!!'] });
add('the root-key refusal with a list of numbers', 'csr_check', { der: rootCsr, root_spkis: [42] });
add('the root-key refusal with a list of one empty string', 'csr_check', { der: rootCsr, root_spkis: [''] });
add('the root-key refusal with no list', 'csr_check', { der: rootCsr });
add('issue_from_csr with an explicit zero validity', 'issue_from_csr', { csr, root_cn: 'A', root_pkcs8: rootPkcs8, now, valid_days: 0 });
add('issue_from_csr over 398 days', 'issue_from_csr', { csr, root_cn: 'A', root_pkcs8: rootPkcs8, now, valid_days: 400 });
add('issue_from_csr with a negative validity', 'issue_from_csr', { csr, root_cn: 'A', root_pkcs8: rootPkcs8, now, valid_days: -1 });
add('issue_from_csr of a request that is not one', 'issue_from_csr', { csr: b64url(new Uint8Array(8)), root_cn: 'A', root_pkcs8: rootPkcs8, now });
add('issue_from_csr refusing the root\'s own key', 'issue_from_csr', { csr: rootCsr, root_cn: 'A', root_pkcs8: rootPkcs8, root_spkis: [rootSpki], now });
add('issue_tbs_from_csr', 'issue_tbs_from_csr', { csr, root_cn: 'A', root_spki: rootSpki, now }, (a) => (a?.tbs ? { ...a, tbs: '<a tbs, whose serial is random>' } : a));
add('issue_from_csr', 'issue_from_csr', { csr, root_cn: 'Alina Rao', root_pkcs8: rootPkcs8, now }, withoutSerial('der'));
add('assemble_leaf with a sig_alg that is not the TBS\'s', 'assemble_leaf', { tbs: leafTbs.tbs, sig: b64url(new Uint8Array(64)), sig_alg: b64url(new Uint8Array([0x30, 0x03, 0x06, 0x01, 0x2a])) });
add('assemble_leaf with no signature', 'assemble_leaf', { tbs: leafTbs.tbs });
add('assemble_root of a TBS that is not one', 'assemble_root', { tbs: b64url(new Uint8Array(4)), sig: b64url(new Uint8Array(64)) });

// §4 cards
add('card_encode', 'card_encode', { fn: 'Alina Rao', cert: leafDer, seal: 'required' });
add('card_encode with a name outside ASCII', 'card_encode', { fn: 'é'.repeat(80), cert: leafDer, seal: 'required' });
add('card_encode with a name that straddles the fold', 'card_encode', { fn: 'a'.repeat(70) + 'ü'.repeat(10), cert: leafDer });
add('card_encode with an emoji name', 'card_encode', { fn: '👋'.repeat(40), cert: leafDer });
add('card_encode with a seal nobody has', 'card_encode', { fn: 'A', cert: leafDer, seal: 'maybe' });
add('card_encode of a certificate that is not one', 'card_encode', { fn: 'A', cert: b64url(new Uint8Array(4)) });
add('card_decode of a real card', 'card_decode', { vcard: card, now });
add('card_decode of an empty card', 'card_decode', { vcard: 'BEGIN:VCARD\r\nEND:VCARD\r\n', now });
add('card_decode of nothing at all', 'card_decode', { vcard: '', now });
add('card_decode of a 1.x card', 'card_decode', { vcard: 'BEGIN:VCARD\r\nVERSION:4.0\r\nX-PACT-VERSION:1\r\nEND:VCARD\r\n', now });
add('card_decode of a card with two certificates', 'card_decode', { vcard: card.replace('END:VCARD', `X-PACT-CERT:${leafDer}\r\nEND:VCARD`), now });
add('card_decode of a card whose certificate is not one', 'card_decode', { vcard: 'BEGIN:VCARD\r\nVERSION:4.0\r\nX-PACT-VERSION:2\r\nX-PACT-CERT:AAAA\r\nEND:VCARD\r\n', now });
add('card_decode after the leaf expired', 'card_decode', { vcard: card, now: '2028-01-01T00:00:00Z' });

// §5 envelopes
add('suite_for an Ed25519 key', 'suite_for', { spki: hostSpki });
add('suite_for a P-256 key', 'suite_for', { spki: wasm.call('public_key', { pkcs8: p256Pkcs8 }).spki });
add('seal_request with no recipient', 'seal_request', { sender_pkcs8: hostPkcs8, form: 'chain', method: 'tools/call', params: {}, msg_id: 'x', ts: 1, ephemeral_seed: b64url(new Uint8Array(32).fill(7)) });
add('seal_request with a form nobody has', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'sideways', method: 'tools/call', params: {}, msg_id: 'x', ts: 1, ephemeral_seed: b64url(new Uint8Array(32).fill(7)) });
add('seal_request with a method nobody has', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/dance', params: {}, msg_id: 'x', ts: 1, ephemeral_seed: b64url(new Uint8Array(32).fill(7)) });
add('seal_request with an empty msg_id', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: {}, msg_id: '', ts: 1, ephemeral_seed: b64url(new Uint8Array(32).fill(7)) });
add('seal_request whose exp is a month past its ts', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: {}, msg_id: 'x', ts: 1, exp: 1 + 31 * 86400, ephemeral_seed: b64url(new Uint8Array(32).fill(7)) });
add('hpke_open of a ciphertext that is not one', 'hpke_open', { suite: 'PACT-SEAL-X25519', recipient_pkcs8: hostPkcs8, info: 'PACT-SEAL-v2', aad: '', enc: b64url(new Uint8Array(32)), ct: b64url(new Uint8Array(32)) });
add('hpke_seal with a suite nobody has', 'hpke_seal', { suite: 'PACT-SEAL-ROT13', recipient_spki: hostSpki, info: 'x', aad: '', plaintext: '' });
// Likewise `decide`: every case below refuses, and its refusal lives in `result.code`, not in a
// top-level `error` — so it too was counted as proven whole on a success it had never given. This
// is the one that reaches the contact tier, where `tier`, `root`, `endpoint`, `method`, `form`,
// `params`, `leaf` and `effects` are all populated and comparable.
add('decide on an envelope from a pinned contact', 'decide', { now, envelope: sealed, node: { ...node, pins: [{ root: rootFp, endpoint: ENDPOINT, leaf: leafDer, state: 'active' }] } });
// A call that names no tool, from a pinned contact: the answer's `tool` member is the one the Go
// port omits and the Rust core sets to null. Nothing reached it before, because every decide case
// either refused early or carried a tool name.
add('decide on a pinned contact\'s call that names no tool', 'decide', { now, envelope: sealedNoTool, node: { ...node, pins: [{ root: rootFp, endpoint: ENDPOINT, leaf: leafDer, state: 'active' }] } });
add('decide on an envelope for a key nobody holds', 'decide', { now, envelope: sealed, node: { ...node, keys: [] } });
add('decide on a real envelope from a stranger', 'decide', { now, envelope: sealed, node });
add('decide on an envelope whose signature is wrong', 'decide', { now, envelope: { ...sealed, sig: b64url(new Uint8Array(64)) }, node });
add('decide on a header that is not JSON', 'decide', { now, envelope: { ...sealed, protected: b64url(new Uint8Array([1, 2, 3])) }, node });
add('decide with no node at all', 'decide', { now, envelope: sealed });
add('decide on an envelope long past its exp', 'decide', { now: '2027-01-01T00:00:00Z', envelope: sealed, node });
// An `exp` of 2^41 — past any plausible year. A first fix for an i64 wrap bounded the timestamps to a
// band before the arithmetic, and so answered "outside the time window" here where the other port
// answers "exp too far from ts": a divergence introduced by the fix for one. Exact arithmetic now.
add('decide on an envelope whose exp is in the year 71,000', 'decide', { now, envelope: wasm.call('seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: { name: 'send_message' }, msg_id: 'parity-far', ts: Math.floor(Date.parse(now) / 1000), exp: 2 ** 41, ephemeral_seed: b64url(new Uint8Array(32).fill(6)) }), node });
add('open_result of a request envelope', 'open_result', { envelope: sealed, my_pkcs8: hostPkcs8, msg_id: 'p-1', now, pins: [] });
add('follow_renewed on a chain to another root', 'follow_renewed', { answer: { code: 'certificate_renewed', data: { chain: [leafDer, rootDer] } }, pinned_root: 'sha256:' + 'A'.repeat(43), pinned_leaf: leafDer, dialed: ENDPOINT, now });
add('follow_renewed on a chain that is not one', 'follow_renewed', { answer: { code: 'certificate_renewed', data: { chain: [] } }, pinned_root: rootFp, pinned_leaf: leafDer, dialed: ENDPOINT, now });
add('follow_renewed on the same leaf', 'follow_renewed', { answer: { code: 'certificate_renewed', data: { chain: [leafDer, rootDer] } }, pinned_root: rootFp, pinned_leaf: leafDer, dialed: ENDPOINT, now });

// §6 the vault
const SALT = b64url(new Uint8Array(16).fill(3)), NONCE = b64url(new Uint8Array(12).fill(4));
add('vault_seal', 'vault_seal', { passphrase: 'a passphrase', plaintext: { v: 1, roots: [], ledger: [], contacts: [] }, kdf: { m_kib: 8192, t: 1, p: 1 }, salt: SALT, nonce: NONCE });
add('vault_open of what vault_seal made', 'vault_open', { passphrase: 'a passphrase', vault: wasm.call('vault_seal', { passphrase: 'a passphrase', plaintext: { v: 1, roots: [], ledger: [], contacts: [] }, kdf: { m_kib: 8192, t: 1, p: 1 }, salt: SALT, nonce: NONCE }).vault });
add('vault_seal with a nonce that is not 12 bytes', 'vault_seal', { passphrase: 'a passphrase', plaintext: { v: 1 }, kdf: { m_kib: 8192, t: 1, p: 1 }, salt: SALT, nonce: b64url(new Uint8Array(8)) });
add('vault_seal with an empty passphrase', 'vault_seal', { passphrase: '', plaintext: { v: 1 }, kdf: { m_kib: 8192, t: 1, p: 1 } });
add('vault_seal with no plaintext', 'vault_seal', { passphrase: 'a passphrase', kdf: { m_kib: 8192, t: 1, p: 1 } });
add('vault_open with a passphrase that is wrong', 'vault_open', { passphrase: 'wrong', vault: { format: 'pact-vault/1', kdf: { name: 'argon2id', m_kib: 8192, t: 1, p: 1 }, salt: b64url(new Uint8Array(16)), nonce: b64url(new Uint8Array(12)), ct: b64url(new Uint8Array(48)) } });
add('vault_open of a document that is not a vault', 'vault_open', { passphrase: 'x', vault: { format: 'something-else' } });
add('vault_open of no document at all', 'vault_open', { passphrase: 'x' });

// The KDF's range, at BOTH ends and on BOTH paths. These parameters come out of an attacker-supplied
// document and are used before the passphrase is tested, and neither port bounded them the same way:
// Rust had no bounds at all (so `m_kib: 268435455` asked for ~256 GiB and `t: 4e9` never returned),
// Go bounded only the bottom at 8 and then let x/crypto quietly clamp the cost, and `name` was
// checked when opening but ignored when sealing. Every case below is a refusal both ports must word
// alike; the honest ones above already pin what a real caller asks for.
const KDF_EDGES = [
  // Just over each line, not catastrophically over, and the reason is worth writing down: a case in
  // this harness runs against an implementation that may have NO bound, and asking an unbounded
  // Argon2id for 256 GiB or four billion passes hangs or kills the harness rather than testing it —
  // which is what happened here on 2026-09-20. The boundary is what the ports must agree on; the
  // catastrophic values are refused before any derivation and are asserted in the Rust unit tests.
  // The MEMORY ceiling is deliberately not here: one KiB over it is still a 2 GiB allocation, which an
  // unbounded implementation attempts. Both ports' unit tests assert it, where the bound exists and the
  // refusal costs nothing.
  ['a KDF one pass over the ceiling', { name: 'argon2id', m_kib: 65536, t: 17, p: 1 }],
  ['a KDF below the floor', { name: 'argon2id', m_kib: 8, t: 1, p: 1 }],
  ['a KDF whose m_kib does not fit in 32 bits', { name: 'argon2id', m_kib: 4294967304, t: 3, p: 1 }],
  ['a KDF with no passes', { name: 'argon2id', m_kib: 65536, t: 0, p: 1 }],
  ['a KDF with too many lanes', { name: 'argon2id', m_kib: 65536, t: 3, p: 99 }],
  ['a KDF nobody implements', { name: 'scrypt', m_kib: 65536, t: 3, p: 1 }],
];
for (const [what, kdf] of KDF_EDGES) {
  add(`vault_seal with ${what}`, 'vault_seal', { passphrase: 'a passphrase', plaintext: { v: 1 }, kdf, salt: SALT, nonce: NONCE });
  add(`vault_open of a document with ${what}`, 'vault_open', { passphrase: 'a passphrase', vault: { format: 'pact-vault/1', kdf, salt: SALT, nonce: NONCE, ct: b64url(new Uint8Array(32)) } });
}
add('wallet_issue', 'wallet_issue', { vault_plaintext: vault, root_fingerprint: rootFp, csr, now, valid_days: 365 }, withoutSerial('der'));
add('wallet_issue for a root the vault does not hold', 'wallet_issue', { vault_plaintext: vault, root_fingerprint: 'sha256:' + 'A'.repeat(43), csr, now });
add('wallet_issue of the root\'s own key', 'wallet_issue', { vault_plaintext: vault, root_fingerprint: rootFp, csr: rootCsr, now });
const moved = { ...vault, ledger: [{ root: rootFp, leaf: '', endpoint: 'https://elsewhere.example/mcp', not_before: '2026-09-10T00:00:00Z', not_after: '2027-09-10T00:00:00Z', issued_at: '2026-09-10T00:00:00Z' }] };
add('wallet_issue for a second address', 'wallet_issue', { vault_plaintext: moved, root_fingerprint: rootFp, csr, now });
add('wallet_issue as a move', 'wallet_issue', { vault_plaintext: moved, root_fingerprint: rootFp, csr, now, move: true }, withoutSerial('der'));
add('wallet_issue with an empty vault', 'wallet_issue', { vault_plaintext: { v: 1, roots: [], ledger: [], contacts: [] }, root_fingerprint: rootFp, csr, now });

// A request the seed can make and both ports must answer identically: the header carries the rules.
add('seal_request', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: { name: 'send_message' }, msg_id: 'p-2', ts: Math.floor(Date.parse(now) / 1000), ephemeral_seed: b64url(new Uint8Array(32).fill(7)) });
add('seal_request with no msg_id at all', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: {}, ts: 1, ephemeral_seed: b64url(new Uint8Array(32).fill(7)) });
add('seal_request with an ephemeral_seed, which neither port takes', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: {}, msg_id: 'x', ts: 1, ephemeral_seed: b64url(new Uint8Array(32)) });
add('seal_result', 'seal_result', { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, result: { ok: true }, msg_id: 'p-1', ts: Math.floor(Date.parse(now) / 1000), ephemeral_seed: b64url(new Uint8Array(32).fill(7)) });
add('seal_result with no recipient', 'seal_result', { sender_pkcs8: hostPkcs8, result: {}, msg_id: 'x', ts: 1, ephemeral_seed: b64url(new Uint8Array(32).fill(7)) });
add('seal_result with neither a result nor an error', 'seal_result', { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, msg_id: 'x', ts: 1, ephemeral_seed: b64url(new Uint8Array(32).fill(7)) });

// §9's root-key refusal reaches a root given as its key id, which is the form a wallet holding
// fingerprints has. One port matched only the SubjectPublicKeyInfo, so the other refusal never fired.
const rootKeyId = wasm.call('key_info', { spki: rootSpki }).key_id;
add('the root-key refusal against a key id', 'csr_check', { der: rootCsr, root_spkis: [rootKeyId] });
add('issue_from_csr refusing a root given as a key id', 'issue_from_csr', { csr: rootCsr, root_cn: 'A', root_pkcs8: rootPkcs8, root_spkis: [rootKeyId], now });

// A key whose algorithm the profile does not admit: it must be refused by name, and a certificate
// carrying one must still reach `profile_error`, which is the thing that says what is wrong with it.
const rsaSpki = b64url(new Uint8Array((await import('node:crypto')).generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' })));
add('key_info of an RSA key', 'key_info', { spki: rsaSpki });
add('public_key of an RSA key', 'public_key', { pkcs8: rsaSpki });
add('suite_for an RSA key', 'suite_for', { spki: rsaSpki });

// Every member that is absent rather than empty, which is the distinction a port loses when its
// zero value and its missing value are the same thing.
for (const [fn, args] of [
  ['key_info', {}], ['public_key', {}], ['sign', {}], ['verify', {}], ['suite_for', {}],
  ['parse_certificate', {}], ['profile_error', {}], ['compare_leaves', {}], ['is_normal_https', {}],
  ['address_guard', {}], ['ip_is_private', {}], ['csr_new', {}], ['csr_check', {}],
  ['validate_chain', { now }], ['generate_key', {}], ['key_from_seed', {}],
  ['build_root', { cn: 'A', not_before: now }], ['assemble_root', {}], ['assemble_leaf', {}],
  ['card_encode', {}], ['card_decode', { now }],
  ['hpke_seal', {}], ['hpke_open', {}], ['seal_request', {}], ['seal_result', {}],
  ['open_result', {}], ['follow_renewed', {}], ['decide', { now }],
  ['vault_seal', { passphrase: 'a passphrase' }], ['vault_open', { passphrase: 'x' }], ['wallet_issue', {}],
]) add(`${fn} with nothing to work from`, fn, args, fn.startsWith('seal_') ? ['error', 'why', 'protected'] : '*');

// The same members present as the JSON literal `null`, which a decoder can quietly read as empty.
for (const [fn, k] of [['key_info', 'spki'], ['parse_certificate', 'der'], ['csr_check', 'der'], ['compare_leaves', 'pinned']])
  add(`${fn} with ${k} as null`, fn, { [k]: null, presented: leafDer, now });
add('csr_check with root_spkis as null', 'csr_check', { der: rootCsr, root_spkis: null });
add('validate_chain with chain as null', 'validate_chain', { chain: null, now });

// ── one succeeding, whole-answer case per function ─────────────────────────────────────────────
// The gate below insists on these. A refusal compared whole proves both ports refuse alike; only a
// success compares the members a caller actually reads, which is where a member goes missing.
const SEED32 = b64url(new Uint8Array(32).fill(11));
add('key_from_seed', 'key_from_seed', { alg: 'ed25519', seed: SEED32 });
add('prf_salt', 'prf_salt', {});
for (const info of ['pact/root/1', 'pact/store-key/1', 'pact/store-id/1']) {
  add(`derive_seed for ${info}`, 'derive_seed', { prf: SEED32, info });
}
add('key_from_seed of a P-256 key', 'key_from_seed', { alg: 'p256', seed: SEED32 });
add('public_key', 'public_key', { pkcs8: hostPkcs8 });
add('public_key of a P-256 key', 'public_key', { pkcs8: p256Pkcs8 });
add('key_info', 'key_info', { spki: hostSpki });
add('key_info of a P-256 key', 'key_info', { spki: wasm.call('public_key', { pkcs8: p256Pkcs8 }).spki });
// Ed25519 is deterministic, so the signature itself is compared; P-256's ECDSA is not, so the
// signature is described and `verify` below proves each port accepts the other's.
add('sign', 'sign', { pkcs8: hostPkcs8, data: b64url(new Uint8Array([1, 2, 3, 4])) });
add('sign with a P-256 key', 'sign', { pkcs8: p256Pkcs8, data: b64url(new Uint8Array([1, 2, 3, 4])) }, (a) => (a?.sig ? { ...a, sig: '<an ECDSA signature>' } : a));
add('verify a signature the other port made', 'verify', { spki: hostSpki, data: b64url(new Uint8Array([1, 2, 3, 4])), sig: go.call('sign', { pkcs8: hostPkcs8, data: b64url(new Uint8Array([1, 2, 3, 4])) }).sig });
add('profile_error of a leaf read as a leaf', 'profile_error', { der: leafDer, kind: 'leaf' });
add('profile_error of a root read as a root', 'profile_error', { der: rootDer, kind: 'root' });

// The external-signing seam, end to end: the core makes the bytes, a signature comes back, the core
// assembles — and the certificate it assembles is the one the other port assembles.
const rootTbs = wasm.call('root_tbs', { cn: 'Alina Rao', spki: rootSpki, not_before: now, serial: SERIAL });
add('assemble_root', 'assemble_root', { tbs: rootTbs.tbs, sig_alg: rootTbs.sig_alg, sig: wasm.call('sign', { pkcs8: rootPkcs8, data: rootTbs.tbs }).sig });
add('assemble_leaf', 'assemble_leaf', { tbs: leafTbs.tbs, sig_alg: leafTbs.sig_alg, sig: wasm.call('sign', { pkcs8: rootPkcs8, data: leafTbs.tbs }).sig });

// HPKE with a fixed ephemeral is reproducible, which is what makes it comparable at all.
const EPH32 = b64url(new Uint8Array(32).fill(5));
const hpkeArgs = { suite: 'PACT-SEAL-X25519', recipient_spki: hostSpki, info: 'PACT-SEAL-v2', aad: b64url(new Uint8Array([9])), plaintext: b64url(new Uint8Array([1, 2, 3])), ephemeral_seed: EPH32 };
add('hpke_seal', 'hpke_seal', hpkeArgs);
const sealedHpke = wasm.call('hpke_seal', hpkeArgs);
add('hpke_open of what hpke_seal made', 'hpke_open', { suite: 'PACT-SEAL-X25519', recipient_pkcs8: hostPkcs8, info: 'PACT-SEAL-v2', aad: b64url(new Uint8Array([9])), enc: sealedHpke.enc, ct: sealedHpke.ct });

// A result sealed and opened: the one path a caller reads members other than `ok` from.
const resultArgs = { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], result: { ok: true, items: [1, 2] }, msg_id: 'p-1', ts: Math.floor(Date.parse(now) / 1000), ephemeral_seed: EPH32 };
add('seal_result of a real result', 'seal_result', resultArgs);
add('open_result of what seal_result made', 'open_result', { envelope: wasm.call('seal_result', resultArgs), my_pkcs8: hostPkcs8, msg_id: 'p-1', now, pins: [] });

// ── comparison ─────────────────────────────────────────────────────────────────────────────────
// Members are compared by name, not by the order a language's encoder happens to emit them in (Go
// sorts a map's keys; serde keeps insertion order). Order is not part of the contract.
const canonical = (v) => {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])]));
  return v;
};
const pick = (o, how, port) =>
  canonical(how === '*' ? o : typeof how === 'function' ? how(o, port) : Object.fromEntries(how.map((k) => [k, o?.[k]])));
const answer = (port, fn, args) => {
  try { return port.call(fn, args); } catch (e) { return { threw: String(e.message || e) }; }
};

const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : null;
let bad = 0;
let ran = 0;
// Which functions were compared whole on an answer that SUCCEEDED. A refusal compared whole proves
// only that both ports refuse alike; it says nothing about the members of the answer a caller
// actually uses, and that is where `card_decode` lost its entire `leaf`.
//
// "Succeeded" has to be asked of the ANSWER's own shape, not of a top-level `error`. This tested
// `!raw.error`, and two functions never put their refusal there: `decide` answers
// `{result:{code:"envelope_invalid"}, effects:[]}` and `csr_check` answers `{ok:false, why}`. So
// both were recorded as proven whole on a success while every one of their cases was a refusal —
// and the richest answers in the contract (`decide`'s tier/root/endpoint/method/form/params/leaf
// /effects, `csr_check`'s cn/spki/fingerprint/alg/endpoint/dns_name) were guarded by nothing. That
// is how `decide`'s `tool` member came to be absent in Go and `null` in Rust with the gate green.
const succeeded = (raw) =>
  raw && !raw.error && !raw.threw && raw.ok !== false && !(raw.result && raw.result.code && raw.result.code !== 'ok');
const provenWhole = new Set();
// ── 2026-09-21: what the Go port answered differently (review-findings plan, B) ────────────────
//
// Each of these was RED against the Go port before the port was changed, and that is the only
// reason to believe it looks at what it names. The 2026-09-20 review read both sides and found
// them; the harness had not, because every `open_result` case either failed at `cty` or succeeded,
// no `decide` case carried a malformed member or an unreadable row of the node's own state, and
// both CSRs were well formed.
{
  const callerKey = ed25519FromSeed(seed('parity/caller'));
  const callerPkcs8 = b64url(pkcs8Of(callerKey.priv));
  const callerSpki = wasm.call('public_key', { pkcs8: callerPkcs8 }).spki;
  const at = (iso) => Math.floor(Date.parse(iso) / 1000);
  const answerTo = (o = {}) => wasm.call('seal_result', { recipient_spki: callerSpki, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], result: { ok: 1 }, msg_id: 'r-1', ts: at(now), ...o });
  const open = (envelope, o = {}) => ({ envelope, my_pkcs8: callerPkcs8, msg_id: 'r-1', now, pins: [], expected_root: rootFp, expected_endpoint: ENDPOINT, ...o });
  const reheader = (e, patch) => ({ ...e, protected: b64url(Buffer.from(JSON.stringify(Object.fromEntries(Object.entries({ ...JSON.parse(Buffer.from(e.protected, 'base64url').toString()), ...patch }).sort(([a], [b]) => (a < b ? -1 : 1)))))) });
  const chainForm = answerTo();
  const leafForm = answerTo({ form: 'leaf' });
  const pinned = [{ root: rootFp, endpoint: ENDPOINT, leaf: leafDer, state: 'active' }];

  // B1 — OpenResult: Rust's words, and Rust's order.
  add('open_result with a key the envelope is not sealed to', 'open_result', open(chainForm, { my_pkcs8: rootPkcs8 }));
  add('open_result whose header names a suite that is known and is not this key\'s', 'open_result', open(reheader(chainForm, { suite: 'PACT-SEAL-P256' })));
  add('open_result with the wrong key AND the wrong suite: which is said first', 'open_result', open(reheader(chainForm, { suite: 'PACT-SEAL-P256' }), { my_pkcs8: rootPkcs8 }));
  add('open_result in the leaf form, naming a leaf no pin holds', 'open_result', open(leafForm));
  add('open_result in the leaf form, from a held leaf that has run out', 'open_result', open(answerTo({ form: 'leaf', ts: at('2027-10-01T00:00:00Z') }), { pins: pinned, now: '2027-10-01T00:00:00Z' }));
  add('open_result in the leaf form, with a signature that is not the held leaf\'s', 'open_result', open({ ...leafForm, sig: b64url(new Uint8Array(64)) }, { pins: pinned }));
  add('open_result in the leaf form, from a held leaf: the answer that succeeds', 'open_result', open(leafForm, { pins: pinned }));

  // B2 — a member that is not base64url at all.
  add('decide on an envelope whose enc is not base64url', 'decide', { now, envelope: { ...sealed, enc: '!!!' }, node });
  add('decide on an envelope whose ct is not base64url', 'decide', { now, envelope: { ...sealed, ct: '!!!' }, node });
  // A stray character beside bytes that are otherwise right. A lenient reader skips it, the signature
  // still verifies — it covers the DECODED bytes — and the envelope is accepted: two spellings of one
  // envelope, and a port that refuses the second while the other takes it.
  add('decide on a real envelope whose protected carries a stray character', 'decide', { now, envelope: { ...sealed, protected: `${sealed.protected}!` }, node });
  add('decide on a real envelope whose enc carries a stray character', 'decide', { now, envelope: { ...sealed, enc: `${sealed.enc}!` }, node });
  add('decide on a real envelope whose sig carries a stray character', 'decide', { now, envelope: { ...sealed, sig: `${sealed.sig}!` }, node });
  add('open_result on a real answer whose protected carries a stray character', 'open_result', open({ ...chainForm, protected: `${chainForm.protected}!` }));
  add('open_result on a real answer whose ct carries a stray character', 'open_result', open({ ...chainForm, ct: `${chainForm.ct}!` }));
  // …and the quieter second spelling: a last character whose UNUSED low bits are set. It decodes to the
  // same bytes in a reader that does not look, so the signature verifies over them.
  const A64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const respell = (s) => {
    const spare = [0, 0, 4, 2][s.length % 4]; // unused bits in the last character of an unpadded string
    const i = A64.indexOf(s.at(-1));
    return spare && (i & ((1 << spare) - 1)) === 0 ? s.slice(0, -1) + A64[i | 1] : null;
  };
  // The other spellings a forgiving reader takes: padding, the standard alphabet, whitespace. Both
  // ports forgave these in an envelope, consistently — and an envelope member has ONE spelling (§13.1).
  const pad = (s) => s + '='.repeat((4 - (s.length % 4)) % 4);
  const std = (s) => s.replace(/-/g, '+').replace(/_/g, '/');
  for (const member of ['protected', 'enc', 'ct', 'sig']) {
    if (pad(sealed[member]) !== sealed[member]) add(`decide on a real envelope whose ${member} is padded`, 'decide', { now, envelope: { ...sealed, [member]: pad(sealed[member]) }, node });
    if (std(sealed[member]) !== sealed[member]) add(`decide on a real envelope whose ${member} uses the standard alphabet`, 'decide', { now, envelope: { ...sealed, [member]: std(sealed[member]) }, node });
    add(`decide on a real envelope whose ${member} has a line break in it`, 'decide', { now, envelope: { ...sealed, [member]: `${sealed[member].slice(0, 8)}\n${sealed[member].slice(8)}` }, node });
    add(`decide on a real envelope whose ${member} has a space in it`, 'decide', { now, envelope: { ...sealed, [member]: `${sealed[member].slice(0, 8)} ${sealed[member].slice(8)}` }, node });
  }
  add('open_result on a real answer whose enc is padded', 'open_result', open({ ...chainForm, enc: pad(chainForm.enc) }));
  add('open_result on a real answer whose sig has a line break in it', 'open_result', open({ ...chainForm, sig: `${chainForm.sig.slice(0, 8)}\n${chainForm.sig.slice(8)}` }));
  for (const member of ['protected', 'enc', 'ct', 'sig']) {
    const again = respell(sealed[member]);
    if (again) add(`decide on a real envelope whose ${member} is spelled with its spare bits set`, 'decide', { now, envelope: { ...sealed, [member]: again }, node });
  }

  // B3 — the node's OWN state, unreadable. The seed throws; so does the core.
  const small = wasm.call('seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'leaf', method: 'tools/call', params: { name: 'send_message' }, msg_id: 'p-small', ts: at(now) });
  const olderLeaf = b64url(buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: ENDPOINT, notBefore: new Date('2026-08-01T00:00:00Z'), notAfter: new Date('2027-08-01T00:00:00Z'), label: 'parity/older-leaf' }));
  add('decide when a held key\'s own leaf will not parse', 'decide', { now, envelope: sealed, node: { ...node, keys: [{ ...node.keys[0], leaf: '!!!' }] } });
  add('decide in the small form when a pin\'s leaf will not parse', 'decide', { now, envelope: small, node: { ...node, pins: [{ root: rootFp, endpoint: ENDPOINT, leaf: 'AAAA', state: 'active' }] } });
  add('decide when the pinned leaf of the sender\'s root will not compare', 'decide', { now, envelope: sealed, node: { ...node, pins: [{ root: rootFp, endpoint: ENDPOINT, leaf: 'AAAA', state: 'active' }] } });
  add('decide when a tombstone\'s instant will not parse', 'decide', { now, envelope: sealed, node: { ...node, tombstones: [{ root: rootFp, at: 'soon', leaf: olderLeaf }] } });
  add('decide when a tombstone\'s leaf will not compare', 'decide', { now, envelope: sealed, node: { ...node, tombstones: [{ root: rootFp, at: '2026-09-10T00:00:00Z', leaf: 'AAAA' }] } });
  add('decide with two tombstones for one root, the FIRST of them stale', 'decide', { now, envelope: sealed, node: { ...node, tombstones: [{ root: rootFp, at: '2026-01-01T00:00:00Z', leaf: olderLeaf }, { root: rootFp, at: '2026-09-10T00:00:00Z', leaf: olderLeaf }] } });
  add('decide on a peer who returns after removal: the answer that succeeds', 'decide', { now, envelope: sealed, node: { ...node, tombstones: [{ root: rootFp, at: '2026-09-10T00:00:00Z', leaf: olderLeaf }] } });

  // B4 — follow_renewed.
  const follow = (answer) => ({ answer, pinned_root: rootFp, pinned_leaf: leafDer, dialed: ENDPOINT, now });
  add('follow_renewed on an answer that is some other code', 'follow_renewed', follow({ code: 'something_else' }));
  add('follow_renewed on a certificate_renewed answer with no data at all', 'follow_renewed', follow({ code: 'certificate_renewed' }));
  add('follow_renewed on a certificate_renewed answer whose data has no chain', 'follow_renewed', follow({ code: 'certificate_renewed', data: {} }));
  add('follow_renewed on a chain that is null', 'follow_renewed', follow({ code: 'certificate_renewed', data: { chain: null } }));
  add('follow_renewed on a chain that is not a list', 'follow_renewed', follow({ code: 'certificate_renewed', data: { chain: 'AAAA' } }));
  add('follow_renewed on a chain whose members are not base64url', 'follow_renewed', follow({ code: 'certificate_renewed', data: { chain: ['!!!', '!!!'] } }));
  add('follow_renewed on a chain of none', 'follow_renewed', follow({ code: 'certificate_renewed', data: { chain: [] } }));
  add('follow_renewed to a leaf OLDER than the one pinned', 'follow_renewed', follow({ code: 'certificate_renewed', data: { chain: [olderLeaf, rootDer] } }));

  // B5 — a request a wallet is asked to SIGN. Laxer than the other port is the wrong direction.
  const [cri, sigAlg] = derChildren(derRead(Buffer.from(csr, 'base64url')));
  const [version, subject, spki, attributes] = derChildren(cri);
  const signedBy = (key, info, alg = sigAlg.raw) => b64url(derSeq(info, alg, derBitstr(signDetached(key.priv, info))));
  const atv = derChildren(derChildren(derChildren(subject)[0])[0]);
  const threePartName = derSeq(derSet(derSeq(atv[0].raw, atv[1].raw, derTlv(0x05, Buffer.alloc(0)))));
  add('csr_check: a commonName attribute with a third element', 'csr_check', { der: signedBy(hostKey, derSeq(version.raw, threePartName, spki.raw, attributes.raw)) });
  add('csr_check: a CertificationRequestInfo that is a SET, not a SEQUENCE', 'csr_check', { der: signedBy(hostKey, derTlv(0x31, cri.content)) });
  add('csr_check: a signatureAlgorithm with a trailing NULL', 'csr_check', { der: signedBy(hostKey, cri.raw, derSeq(derChildren(sigAlg)[0].raw, derTlv(0x05, Buffer.alloc(0)))) });
  const x25519Spki = x25519FromSeed(seed('parity/x25519')).pub.export({ format: 'der', type: 'spki' });
  add('csr_check: a key outside the profile AND a malformed attribute set: which is said first', 'csr_check', { der: signedBy(hostKey, derSeq(version.raw, subject.raw, x25519Spki, derTlv(0xa0, derInt(7)))) });

  // A member that is ABSENT is `<name> is required` and `bad_request`, whatever its type. For an
  // instant the Go port said "an instant is required" and called it `parse` — in every function that
  // takes one — and no case here had ever left `now` out.
  add('validate_chain with no now', 'validate_chain', { chain: [leafDer, rootDer] });
  add('decide with no now', 'decide', { envelope: sealed, node });
  add('open_result with no now', 'open_result', { ...open(chainForm), now: undefined });
  add('follow_renewed with no now', 'follow_renewed', { ...follow({ code: 'certificate_renewed', data: { chain: [leafDer, rootDer] } }), now: undefined });
  add('card_decode with no now', 'card_decode', { vcard: card });
  add('issue_from_csr with no now', 'issue_from_csr', { csr, root_pkcs8: rootPkcs8, root_cn: 'Alina Rao' });
  add('build_leaf with no not_before', 'build_leaf', { cn: 'Alina Rao', root_cn: 'Alina Rao', root_pkcs8: rootPkcs8, host_spki: hostSpki, endpoint: ENDPOINT, not_after: '2027-09-01T00:00:00Z' });
  add('validate_chain with a now that is there and is not an instant', 'validate_chain', { chain: [leafDer, rootDer], now: 'soon' });
  add('validate_chain with a now that is empty', 'validate_chain', { chain: [leafDer, rootDer], now: '' });

  // C9 — a chain that is THERE and will not read is not a chain that was left out.
  const sealing = (o) => ({ recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', method: 'tools/call', params: {}, msg_id: 'c9', ts: at(now), ephemeral_seed: b64url(seed('parity/c9')), ...o });
  add('seal_request in the chain form with no sender_chain', 'seal_request', sealing({}));
  add('seal_request whose sender_chain is not base64url', 'seal_request', sealing({ sender_chain: ['!!!', '!!!'] }));
  add('seal_request whose sender_chain is not a list', 'seal_request', sealing({ sender_chain: 'AAAA' }));
  add('seal_result whose sender_chain is not base64url', 'seal_result', { recipient_spki: callerSpki, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: ['!!!'], result: {}, msg_id: 'c9', ts: at(now) });

  // C8 — RFC 8410: an Ed25519 AlgorithmIdentifier carries no parameters, in a private key either.
  {
    const [pv, , pk] = derChildren(derRead(Buffer.from(hostPkcs8, 'base64url')));
    const oidOnly = derChildren(derChildren(derRead(Buffer.from(hostPkcs8, 'base64url')))[1])[0];
    const withNull = b64url(derSeq(pv.raw, derSeq(oidOnly.raw, derTlv(0x05, Buffer.alloc(0))), pk.raw));
    add('public_key from an Ed25519 PKCS #8 whose algorithm carries a NULL', 'public_key', { pkcs8: withNull });
    add('sign with an Ed25519 PKCS #8 whose algorithm carries a NULL', 'sign', { pkcs8: withNull, data: b64url(Buffer.from('x')) });
  }

  // ── C: what reached the pinned core. Both ports were wrong the SAME way on most of these, so parity
  // could not have seen them; each port's own tests were red first, and these hold the two together.
  {
    const shortAki = b64url(buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: ENDPOINT, notBefore: new Date('2026-09-01T00:00:00Z'), notAfter: new Date('2027-09-01T00:00:00Z'), aki: Buffer.from([1, 2, 3]), label: 'parity/short-aki' }));
    add('parse_certificate of a leaf naming its issuer in three bytes', 'parse_certificate', { der: shortAki });
    add('validate_chain of a leaf naming its issuer in three bytes', 'validate_chain', { chain: [shortAki, rootDer], now });
    add('card_decode of a card whose leaf names its issuer in three bytes', 'card_decode', { vcard: wasm.call('card_encode', { fn: 'Alina Rao', cert: shortAki }).vcard, now });

    for (const ip of ['64:ff9b::7f00:1', '64:ff9b::a9fe:a9fe', '64:ff9b::808:808', '64:ff9b:1::1', '2002:7f00:1::1', '2002:808:808::1', 'fec0::1', '::7f00:1', '::808:808', '2606:4700:4700::1111', '::ffff:127.0.0.1', '::1', '::'])
      add(`ip_is_private ${ip}`, 'ip_is_private', { ip });
    for (const endpoint of ['https://[64:ff9b::7f00:1]/mcp', 'https://[2002:c0a8:101::1]/mcp', 'https://[64:ff9b::808:808]/mcp', 'https://[2606:4700:4700::1111]/mcp'])
      add(`address_guard ${endpoint}`, 'address_guard', { endpoint, guest: true });

    const E8443 = 'https://agent.alina.example:8443/mcp';
    const csr8443 = wasm.call('csr_new', { cn: 'Alina Rao', host_pkcs8: hostPkcs8, endpoint: E8443, dns_name: 'agent.alina.example' }).der;
    add('csr_check on another port, asking for the host\'s dNSName', 'csr_check', { der: csr8443 });
    add('csr_check on another port, asking for some other dNSName', 'csr_check', { der: wasm.call('csr_new', { cn: 'Alina Rao', host_pkcs8: hostPkcs8, endpoint: E8443, dns_name: 'agent.mallory.example' }).der });
    const leaf8443 = b64url(buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: E8443, dnsName: 'agent.alina.example', notBefore: new Date('2026-09-01T00:00:00Z'), notAfter: new Date('2027-09-01T00:00:00Z'), label: 'parity/8443' }));
    add('validate_chain of a leaf on another port carrying its host\'s dNSName', 'validate_chain', { chain: [leaf8443, rootDer], now, expected_endpoint: E8443 });

    for (const [what, args] of [['a name with CR LF', { fn: 'x\r\nX-PACT-SEAL:none', cert: leafDer, seal: 'required' }], ['a name with a bare LF', { fn: 'x\nX-PACT-SEAL:none', cert: leafDer }], ['a name with a NUL', { fn: 'x\u0000y', cert: leafDer }], ['a seal with CR LF', { fn: 'x', cert: leafDer, seal: 'required\r\nX-PACT-VERSION:3' }], ['an extra line with CR LF', { fn: 'x', cert: leafDer, extra: ['X-A:1\r\nX-PACT-SEAL:none'] }], ['a name with a comma and a semicolon', { fn: 'Rao, Alina; of Pune', cert: leafDer, seal: 'required' }]])
      add(`card_encode: ${what}`, 'card_encode', args);

    const named = wasm.call('key_info', { spki: hostSpki }).fingerprint;
    const mine = { root: rootFp, endpoint: ENDPOINT, leaf: leafDer, state: 'active' };
    const bad = { root: 'sha256:a-row-gone-bad', endpoint: 'https://ghost.example/mcp', leaf: 'AAAA', state: 'active' };
    add('decide, small form: the pin names its leaf', 'decide', { now, envelope: small, node: { ...node, pins: [{ ...mine, leaf_fingerprint: named }] } });
    add('decide, small form: an unreadable pin that names some OTHER leaf is never parsed', 'decide', { now, envelope: small, node: { ...node, pins: [{ ...bad, leaf_fingerprint: 'sha256:somebody-else' }, { ...mine, leaf_fingerprint: named }] } });
    add('decide, small form: an unreadable pin that names no leaf has to be parsed', 'decide', { now, envelope: small, node: { ...node, pins: [bad, { ...mine, leaf_fingerprint: named }] } });
    add('decide, small form: a pin whose named leaf is not its leaf', 'decide', { now, envelope: small, node: { ...node, pins: [{ ...mine, leaf: rootDer, leaf_fingerprint: named }] } });
    add('open_result, leaf form: the pin names its leaf', 'open_result', open(leafForm, { pins: [{ ...mine, leaf_fingerprint: named }] }));
    add('open_result, leaf form: a pin whose named leaf is not its leaf', 'open_result', open(leafForm, { pins: [{ ...mine, leaf: rootDer, leaf_fingerprint: named }] }));

    const sibling = p256FromSeed(seed('parity/card-held-sibling'));
    const siblingDer = b64url(buildRoot({ cn: 'Alina at work', key: sibling, notBefore: new Date('2026-09-01T00:00:00Z'), label: 'parity/sibling' }));
    const siblingCsr = wasm.call('csr_new', { cn: 'A Host', host_pkcs8: b64url(pkcs8Of(sibling.priv)), endpoint: ENDPOINT }).der;
    add('wallet_issue: a request carrying a CARD-held sibling root\'s key', 'wallet_issue', { vault_plaintext: { ...vault, roots: [...vault.roots, { fingerprint: wasm.call('parse_certificate', { der: siblingDer }).fingerprint, cn: 'Alina at work', cert: siblingDer, holder: { kind: 'piv' } }] }, root_fingerprint: rootFp, csr: siblingCsr, now });
  }

  // B7 — `now` is whole seconds. Half a second past a leaf's notAfter is the same second.
  add('validate_chain half a second after the leaf\'s last second', 'validate_chain', { chain: [leafDer, rootDer], now: '2027-09-01T00:00:00.500Z', expected_root: rootFp, expected_endpoint: ENDPOINT });
  add('validate_chain in the leaf\'s last second, with a fraction', 'validate_chain', { chain: [leafDer, rootDer], now: '2027-08-31T23:59:59.900Z', expected_root: rootFp, expected_endpoint: ENDPOINT });
}

for (const [name, fn, args, keys] of cases) {
  if (only && !name.includes(only) && fn !== only) continue;
  ran++;
  const raw = answer(wasm, fn, args);
  if ((keys === '*' || typeof keys === 'function') && succeeded(raw)) provenWhole.add(fn);
  const a = pick(raw, keys, wasm);
  const b = pick(answer(go, fn, args), keys, go);
  const same = JSON.stringify(a) === JSON.stringify(b);
  if (!same) {
    bad++;
    console.log(`  DIFFER  ${name}`);
    console.log(`    wasm ${JSON.stringify(a)}`);
    console.log(`    go   ${JSON.stringify(b)}`);
  } else if (process.argv.includes('--verbose')) {
    console.log(`  agree   ${name}`);
  }
}

// ── the coverage gate ──────────────────────────────────────────────────────────────────────────
//
// A harness that guards a surface has to know when the surface grows, and has to be reading the
// surface rather than a guess at it. Both dispatchers are read here, and three things are asserted:
//
//   1. the two ports dispatch the same names — `version` lived in one dispatcher and not the other
//      until this check was written;
//   2. every name has a case above;
//   3. every name has at least one case compared whole (`'*'`), not through a key list. That is the
//      one that matters: `card_decode` dropped its entire `leaf` member in one port, and no key list
//      would have noticed, because a key list only ever looks at the keys someone thought to name.
const { readFile } = await import('node:fs/promises');
const read = async (f) => readFile(new URL(f, import.meta.url), 'utf8');

// Rust arms: one or more string literals joined by `|` in front of `=>`. Go: the table's own keys,
// at one tab. Both are read as sets of names, which is what the contract's surface is.
const rustNames = new Set(
  [...(await read('../crates/pact-identity/src/api.rs')).matchAll(/^\s{8}("[a-z_0-9]+"(?:\s*\|\s*"[a-z_0-9]+")*)\s*=>/gm)]
    .flatMap((m) => m[1].split('|').map((q) => q.trim().replace(/"/g, ''))),
);
const goNames = new Set(
  [...(await read('../go/api.go')).matchAll(/^\t"([a-z_0-9]+)":\s/gm)].map((m) => m[1]),
);

const problems = [];
if (rustNames.size < 20 || goNames.size < 20) {
  problems.push(`the dispatchers did not read (rust ${rustNames.size}, go ${goNames.size}): this gate is not guarding anything`);
}
const onlyRust = [...rustNames].filter((n) => !goNames.has(n)).sort();
const onlyGo = [...goNames].filter((n) => !rustNames.has(n)).sort();
if (onlyRust.length) problems.push(`only the Rust core dispatches: ${onlyRust.join(', ')}`);
if (onlyGo.length) problems.push(`only the Go port dispatches: ${onlyGo.join(', ')}`);

const surface = new Set([...rustNames, ...goNames]);
surface.delete('version'); // the build, not a rule: its answer describes the port and cannot agree
const covered = new Set(cases.map(([, fn]) => fn));
const whole = provenWhole;
const uncovered = [...surface].filter((f) => !covered.has(f)).sort();
const partial = [...surface].filter((f) => covered.has(f) && !whole.has(f)).sort();
if (uncovered.length) problems.push(`no parity case at all: ${uncovered.join(', ')}`);
if (partial.length) {
  problems.push(
    `never compared whole on an answer that succeeded, so a dropped member would not show: ${partial.join(', ')}`,
  );
}

if (problems.length && !only) {
  console.log('\n  THE GATE IS NOT SATISFIED');
  for (const p of problems) console.log(`    ${p}`);
}

// ── the manifest ───────────────────────────────────────────────────────────────────────────────
//
// `--manifest <path>` writes what was just compared, so the record of these checks is generated
// from the run rather than transcribed from it. It is written ONLY when every case agreed and the
// gate is satisfied, so a manifest describes checks that actually held: a file claiming 270 passing
// cases cannot be produced by a run in which they did not.
//
// That last sentence was here before the condition was. The manifest was written on every run,
// disagreements and all, a few lines above the exit code that says the run failed; `record.mjs`
// was safe only because a non-zero exit throws before it reads the file.
const manifestAt = process.argv[process.argv.indexOf('--manifest') + 1];
const agreed = bad === 0 && problems.length === 0;
if (process.argv.includes('--manifest') && manifestAt && !only && agreed) {
  const byFn = new Map();
  for (const [name, fn] of cases) {
    if (!byFn.has(fn)) byFn.set(fn, []);
    byFn.get(fn).push(name);
  }
  const { writeFileSync } = await import('node:fs');
  writeFileSync(manifestAt, JSON.stringify({
    generated_by: 'js/parity.mjs --manifest',
    cases: cases.length,
    functions: surface.size,
    compared_whole: [...surface].filter((f) => whole.has(f)).length,
    disagreements: bad,
    by_function: [...byFn.entries()].sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([fn, names]) => ({ fn, in_surface: surface.has(fn), compared_whole: whole.has(fn), cases: names })),
  }, null, 2) + '\n');
}

const total = only ? ran : cases.length;
const wholeInSurface = [...surface].filter((f) => whole.has(f)).length;
console.log(`\n${total - bad}/${total} boundary answers agree between the ports${only ? ` (filtered by ${JSON.stringify(only)})` : `; ${surface.size} functions guarded, ${wholeInSurface} of them compared whole`}`);
// `bad` is a COUNT, and process.exit truncates mod 256: with 276 cases, exactly 256 disagreements
// would have exited 0.
process.exit(bad > 0 || (problems.length && !only) ? 1 : 0);
