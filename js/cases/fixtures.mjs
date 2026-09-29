// What the parity cases are handed: the cast's certificates, keys, cards and envelopes, and the ways a
// case compares an answer that carries something drawn fresh. Built from js/cast.mjs by the seed
// library, so no fixture is an answer of the port under test.
//
// Four kinds are still made by a port, because the seed has no builder for them. Each is an input
// that both ports are then asked about, and each is named where it is made:
//   - certificate signing requests (`csr`, `rootCsr`, and three in cases/csr.mjs and cases/vault.mjs):
//     the seed library builds certificates, not requests;
//   - to-be-signed certificates (`leafTbs`, `rootTbs`, and the plan in cases/certificates.mjs): the
//     seed builds whole certificates and exposes no TBS;
//   - a sealed vault (cases/vault.mjs): the seed has no vault;
//   - a sealed RESULT (`answerTo`, and the result in cases/envelopes.mjs): the seed seals requests.
// And one is made by the OTHER port on purpose: 'verify a signature the other port made'.
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { seed, ed25519FromSeed, x25519FromSeed, pkcs8Of, spkiOf, b64url, fingerprint, keyId } from '../../../pact-protocol/vectors/lib/keys.mjs';
import { buildRoot, buildLeaf } from '../../../pact-protocol/vectors/lib/x509.mjs';
import { encodeCard } from '../../../pact-protocol/vectors/lib/card.mjs';
import { read as derRead, children as derChildren, seq as derSeq, oid as derOid, tlv as derTlv, int as derInt, octet as derOctet, bitstr as derBitstr } from '../../../pact-protocol/vectors/lib/der.mjs';
import { signDetached } from '../../../pact-protocol/vectors/lib/hpke.mjs';
import { sealEnvelope } from '../../../pact-protocol/vectors/lib/envelope.mjs';
import { alina, bharat, CLOCK, BORN, DIES, ENDPOINTS } from '../cast.mjs';

export function fixtures({ wasm, go }) {
  const rootKey = alina.root, hostKey = alina.host, p256Key = bharat.root;
  const now = CLOCK;
  const ENDPOINT = ENDPOINTS.alina;
  const at = (iso) => Math.floor(Date.parse(iso) / 1000);
  const rootDerBytes = buildRoot({ cn: 'Alina Rao', key: rootKey, notBefore: BORN, label: 'parity/root' });
  const leafDerBytes = buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: ENDPOINT, notBefore: BORN, notAfter: DIES, label: 'parity/leaf' });
  const rootDer = b64url(rootDerBytes), leafDer = b64url(leafDerBytes);
  const rootPkcs8 = b64url(pkcs8Of(rootKey.priv));
  const hostPkcs8 = b64url(pkcs8Of(hostKey.priv));
  const p256Pkcs8 = b64url(pkcs8Of(p256Key.priv));
  const rootSpki = b64url(spkiOf(rootKey.pub));
  const hostSpki = b64url(spkiOf(hostKey.pub));
  const p256Spki = b64url(spkiOf(p256Key.pub));
  const rootFp = fingerprint(rootKey.pub);
  // Port-built: the seed builds no certificate signing request.
  const csr = wasm.call('csr_new', { cn: 'Alina Rao', host_pkcs8: hostPkcs8, endpoint: ENDPOINT }).der;
  const rootCsr = wasm.call('csr_new', { cn: 'Alina Rao', host_pkcs8: rootPkcs8, endpoint: ENDPOINT }).der;
  const card = encodeCard({ fn: 'Alina Rao', cert: leafDerBytes, seal: 'required' });
  const vault = { v: 2, roots: [{ fingerprint: rootFp, cn: 'Alina Rao', pkcs8: rootPkcs8, cert: rootDer, created: now }] };
  const record = { v: 2, ledger: [], contacts: [] };
  // Port-built: the seed exposes no to-be-signed certificate.
  const leafTbs = wasm.call('leaf_tbs', { cn: 'Alina Rao', root_cn: 'Alina Rao', root_spki: rootSpki, host_spki: hostSpki, endpoint: ENDPOINT, not_before: now, not_after: '2027-09-01T00:00:00Z' });
  const rootTbs = wasm.call('root_tbs', { cn: 'Alina Rao', spki: rootSpki, not_before: now, serial: b64url(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])) });
  // A request from Alina's host to herself, sealed by the seed.
  const request = (o) => sealEnvelope({ senderKey: hostKey, senderChain: [leafDerBytes, rootDerBytes], recipientLeaf: leafDerBytes, ts: at(now), ...o });
  const sealed = request({ params: { name: 'send_message' }, msgId: 'p-1' });
  const sealedNoTool = request({ params: {}, msgId: 'p-1' });
  const node = {
    endpoint: ENDPOINT,
    accept_new_hosts: 'auto',
    chain: [leafDer, rootDer],
    keys: [{ kid: fingerprint(hostKey.pub), leaf: leafDer, pkcs8: hostPkcs8, current: true }],
    former: [], sibling_kids: [], pins: [], tombstones: [], former_endpoints: [], seen: [],
  };
  const pinned = [{ root: rootFp, endpoint: ENDPOINT, leaf: leafDer, state: 'active' }];

  // ── how a case compares an answer ──────────────────────────────────────────────────────────────
  //
  // `'*'` compares the whole answer and is the default, because a member that nobody thought to name
  // is exactly the member that goes missing. Where an answer carries something genuinely per-run — a
  // random serial, a fresh ephemeral — the case passes a FUNCTION that replaces that one value with a
  // description of it, and everything else is still compared. A plain key list is the weakest form and
  // is used only where neither is possible; the runner counts how many functions are compared whole,
  // so weakening a case is visible rather than quiet.
  //
  // Nothing may narrow to `['error']` merely to make a disagreement go away: a differing `why` IS the
  // finding.
  //
  // `shape` keeps the member's presence and size and drops its value, for something drawn fresh.
  const shape = (v) => (typeof v === 'string' ? `<${v.length} chars>` : v === undefined ? undefined : `<${typeof v}>`);
  // `withoutSerial` replaces a base64url certificate or TBS with its parsed form minus the random
  // serial, so everything the profile fixes is still compared byte for byte.
  const parsedMinusSerial = (port, b64) => {
    const c = port.call('parse_certificate', { der: b64 });
    if (c.error) return c;
    const { serial, sig_alg: _s, fingerprint: _f, ...rest } = c;
    return { ...rest, serial: serial ? '<a serial>' : serial }; // its length moves with its leading byte
  };
  const withoutSerial = (member) => (answer, port) => {
    if (!answer?.[member]) return answer;
    const out = { ...answer, [member]: parsedMinusSerial(port, answer[member]) };
    // A serial of 8 bytes may encode in 8 or 9, so the certificate's length moves with it.
    if (out[member]?.bytes) out[member] = { ...out[member], bytes: '<a serial\'s worth>' };
    return out;
  };

  // ── the answers to calls the cases open, decide on and follow ──────────────────────────────────
  const callerKey = ed25519FromSeed(seed('parity/caller'));
  const callerPkcs8 = b64url(pkcs8Of(callerKey.priv));
  const callerSpki = b64url(spkiOf(callerKey.pub));
  // Port-built: the seed seals requests, not results.
  const answerTo = (o = {}) => wasm.call('seal_result', { recipient_spki: callerSpki, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], result: { ok: 1 }, msg_id: 'r-1', ts: at(now), ...o });
  const open = (envelope, o = {}) => ({ envelope, my_pkcs8: callerPkcs8, my_spki: callerSpki, msg_id: 'r-1', now, pins: [], expected_root: rootFp, expected_endpoint: ENDPOINT, ...o });
  const chainForm = answerTo();
  const leafForm = answerTo({ form: 'leaf' });
  const follow = (answer) => ({ answer, pinned_root: rootFp, pinned_leaf: leafDer, dialed: ENDPOINT, now });
  const olderLeaf = b64url(buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: ENDPOINT, notBefore: new Date('2026-08-01T00:00:00Z'), notAfter: new Date('2027-08-01T00:00:00Z'), label: 'parity/older-leaf' }));
  const small = request({ reference: true, params: { name: 'send_message' }, msgId: 'p-small' });

  // Certificates more than one section is asked about.
  const alinaLeaf = (o) => b64url(buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: ENDPOINT, notBefore: BORN, notAfter: DIES, ...o }));
  // A P-256-rooted identity (Bharat's root), and a leaf under it whose ECDSA signature is the high twin.
  const p256RootDer = b64url(buildRoot({ cn: bharat.cn, key: p256Key, notBefore: BORN, label: 'parity/p256root' }));
  const p256Leaf = (misencode = {}) => b64url(buildLeaf({ cn: bharat.cn, rootCn: bharat.cn, root: p256Key, hostKey, endpoint: ENDPOINT, notBefore: BORN, notAfter: DIES, label: 'parity/p256leaf', misencode }));
  const twinLeaf = p256Leaf({ sigTwin: true });
  // A leaf naming its issuer in three bytes.
  const shortAki = alinaLeaf({ aki: Buffer.from([1, 2, 3]), label: 'parity/short-aki' });

  // A key whose algorithm the profile does not admit, fresh each run: it is refused by name wherever
  // it is handed in, so none of its bytes reach an answer.
  const rsaSpki = b64url(generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' }));

  // ── keys outside the profile (R12, T2, T3, T4) ───────────────────────────────────────────────────
  //
  // `outside` holds one value of each contract type that carries a key — Spki, Pkcs8, CertDer, Csr —
  // whose key is Alina's host key with a NULL after the Ed25519 OID, which RFC 8410 does not have:
  // deterministic, the same key in every form, and read by no port as a key. js/cases/generated.mjs
  // puts one into every member of those types. The certificate is the seed's (its subjectKeyIdentifier
  // follows the bytes written); the request is port-built from `csr`, re-signed by the host key.
  const nullParams = derSeq(derOid('1.3.101.112'), derTlv(0x05, Buffer.alloc(0)));
  const withNull = (spki) => derSeq(nullParams, derChildren(derRead(spki))[1].raw);
  const hostSeed = derChildren(derRead(pkcs8Of(hostKey.priv)))[2].content.subarray(2);
  const outsideSpki = withNull(spkiOf(hostKey.pub));
  // A request carrying `spki`, made from `csr` and signed by the host key: its signature verifies
  // under no key it could name, which is not what it is asked about — the key is refused first.
  const requestFor = (spki) => {
    const [info, sigAlg] = derChildren(derRead(Buffer.from(csr, 'base64url')));
    const [version, subject, , attributes] = derChildren(info);
    const cri = derSeq(version.raw, subject.raw, spki, attributes.raw);
    return b64url(derSeq(cri, sigAlg.raw, derBitstr(signDetached(hostKey.priv, cri))));
  };
  const outside = {
    Spki: b64url(outsideSpki),
    Pkcs8: b64url(derSeq(derInt(0), nullParams, derOctet(derOctet(hostSeed)))),
    CertDer: alinaLeaf({ misencode: { spkiAlgOid: '06032b65700500' }, label: 'parity/outside' }),
    Csr: requestFor(outsideSpki),
  };
  // Keys of three algorithms the profile does not have, each a key some platform makes: RSA and
  // P-384 (named by the ecPublicKey OID, the curve beside it) fresh each run, and a bare X25519 key,
  // which one port read as a third algorithm. `foreign[kind]` is `{ spki, oid, pub }`.
  const x25519Pub = x25519FromSeed(seed('parity/x25519')).pub;
  const foreign = {
    rsa: { pub: createPublicKey({ key: Buffer.from(rsaSpki, 'base64url'), format: 'der', type: 'spki' }), oid: '1.2.840.113549.1.1.1' },
    'P-384': { pub: generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).publicKey, oid: '1.2.840.10045.2.1' },
    X25519: { pub: x25519Pub, oid: '1.3.101.110' },
  };
  for (const k of Object.values(foreign)) k.spki = spkiOf(k.pub);
  foreign['Ed25519 with a NULL'] = { spki: outsideSpki, oid: '1.3.101.112' };
  // A leaf under Alina's root carrying one of them. keyUsage is given, as the seed picks it by an
  // algorithm these do not have.
  const foreignLeaf = (kind) => kind === 'Ed25519 with a NULL'
    ? outside.CertDer
    : alinaLeaf({ hostKey: { pub: foreign[kind].pub }, usage: [0], label: `parity/foreign/${kind}` });

  // The constants contract/contract.json carries once for both ports (its `Windows`, `Kdf`, …): a case
  // at an edge reads the edge from here, so it moves with the contract and cannot go stale beside it.
  const defs = JSON.parse(readFileSync(new URL('../../contract/contract.json', import.meta.url), 'utf8')).$defs;
  // An instant `seconds` before `now`, as an argument writes one.
  const before = (seconds) => new Date((at(now) - seconds) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');

  return {
    wasm, go, now, at, ENDPOINT, defs, before,
    rootKey, hostKey, p256Key, callerKey,
    rootDer, leafDer, rootDerBytes, leafDerBytes,
    rootPkcs8, hostPkcs8, p256Pkcs8, callerPkcs8,
    rootSpki, hostSpki, p256Spki, callerSpki, rsaSpki,
    rootFp, rootKeyId: b64url(keyId(rootKey.pub)), hostFp: fingerprint(hostKey.pub),
    csr, rootCsr, card, vault, record, leafTbs, rootTbs,
    request, sealed, sealedNoTool, small, node, pinned,
    answerTo, open, chainForm, leafForm, follow, olderLeaf,
    alinaLeaf, p256RootDer, p256Leaf, twinLeaf, shortAki, outside, foreign, foreignLeaf, requestFor,
    shape, withoutSerial, x25519SpkiDer: spkiOf(x25519FromSeed(seed('parity/x25519')).pub),
    SERIAL: b64url(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])),
    B64_BAD: ['!!!', '', 'AA=', 'a b c', '~~~~'],
  };
}
