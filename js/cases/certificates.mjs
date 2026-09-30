// §2 of the contract: certificates — build, assemble, parse, the profile, chains, and the address rules.
import { b64url } from '../../../pact-protocol/vectors/lib/keys.mjs';
import { buildRoot, parse as seedParse, profileError as seedProfileError } from '../../../pact-protocol/vectors/lib/x509.mjs';
import { ecdsaTwin, ecdsaIsLowS, read as derRead, children as derChildren, seq, tlv } from '../../../pact-protocol/vectors/lib/der.mjs';
import { signDetached } from '../../../pact-protocol/vectors/lib/hpke.mjs';
import { bharat, BORN } from '../cast.mjs';

// An IPv6 literal with a zone id, in every spelling a URL parser might be handed one (T1, C1, R09).
export const ZONED = [
  'https://[2001:db8::1%25eth0]/mcp', 'https://[2001:db8::1%eth0]/mcp', 'https://[fe80::1%eth0]/mcp', 'https://[::1%lo]/mcp',
  'https://[2001:db8::1%x@evil.example]/mcp', 'https://[2001:db8::1%x?y]/mcp', 'https://[2001:db8::1%x#y]/mcp',
  'https://[2001:db8::1%X]/mcp', 'https://[2001:db8::1%25eth0]:8443/mcp',
];

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

export default function certificates({ add, expect }, f) {
  const { now, ENDPOINT, rootKey, hostKey, p256Key, rootDer, leafDer, rootPkcs8, rootSpki, hostSpki, p256Spki, rootFp, leafTbs, rootTbs, SERIAL } = f;
  const URLS = [
    ENDPOINT, 'https://agent.alina.example:8443/mcp', 'https://agent.alina.example:443/mcp', 'https://agent.alina.example/mcp/',
    'https://agent.alina.example/', 'https://agent.alina.example', 'http://agent.alina.example/mcp',
    'https://AGENT.alina.example/mcp', 'https://user@agent.alina.example/mcp', 'https://agent.alina.example/mcp?q=1',
    'https://agent.alina.example/mcp#f', 'https://agent.alina.example/./mcp', 'https://agent.alina.example/a/../mcp',
    'https://agent.alina.example/%2f', 'https://agent.alina.example/%41', 'https://agent.alina.example/a b',
    'https://agent.alina.example:0/mcp', 'https://agent.alina.example:99999/mcp', 'https://agent.alina.example:08443/mcp',
    'https://[2001:db8::1]:8443/mcp', 'https://[2001:db8::1]8443/mcp', '', 'not a url', 'https://',
  ];
  const { alinaLeaf, p256RootDer, p256Leaf, twinLeaf, shortAki } = f;

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
  add('build_root with no key', 'build_root', { cn: 'Alina Rao', not_before: now, serial: SERIAL });
  add('build_root', 'build_root', { cn: 'Alina Rao', pkcs8: rootPkcs8, not_before: now, serial: SERIAL });
  add('root_tbs', 'root_tbs', { cn: 'Alina Rao', spki: rootSpki, not_before: now, serial: SERIAL });
  add('root_tbs with no key', 'root_tbs', { cn: 'Alina Rao', not_before: now, serial: SERIAL });
  add('root_tbs with a serial that is too long', 'root_tbs', { cn: 'A', spki: rootSpki, not_before: now, serial: b64url(new Uint8Array(21)) });
  add('leaf_tbs', 'leaf_tbs', { cn: 'Alina Rao', root_cn: 'Alina Rao', root_spki: rootSpki, host_spki: hostSpki, endpoint: ENDPOINT, not_before: now, not_after: '2027-09-01T00:00:00Z', serial: SERIAL });
  add('leaf_tbs with no issuer', 'leaf_tbs', { cn: 'A', root_cn: 'A', host_spki: hostSpki, endpoint: ENDPOINT, not_before: now, not_after: '2027-09-01T00:00:00Z' });
  add('build_leaf', 'build_leaf', { cn: 'Alina Rao', root_cn: 'Alina Rao', root_pkcs8: rootPkcs8, host_spki: hostSpki, endpoint: ENDPOINT, not_before: now, not_after: '2027-09-01T00:00:00Z', serial: SERIAL });
  // The order build_leaf and leaf_tbs read an optional `serial` in: after the keys, before `cn`, the
  // endpoint and the dates, in both ports. §0's order rule speaks of several missing REQUIRED members;
  // a bad optional one beside a missing required one is a reading both ports share, held here so that
  // neither moves alone (an observation of the port-parity verification, 2026-09-30).
  for (const [fn, keys] of [['build_leaf', { root_pkcs8: rootPkcs8 }], ['leaf_tbs', { root_spki: rootSpki }]]) {
    const id = `${fn} with a serial that is too short and no cn`;
    add(id, fn, { root_cn: 'A', ...keys, host_spki: hostSpki, endpoint: ENDPOINT, not_before: now, not_after: '2027-09-01T00:00:00Z', serial: b64url(new Uint8Array(4)) });
    expect(id, { error: 'bad_request', why: 'serial is 8 to 20 bytes' });
  }
  add('build_root with a serial that is too short', 'build_root', { cn: 'Alina Rao', pkcs8: rootPkcs8, not_before: now, serial: b64url(new Uint8Array(4)) });
  add('build_root with an instant that is not one', 'build_root', { cn: 'Alina Rao', pkcs8: rootPkcs8, not_before: 'yesterday', serial: SERIAL });
  add('build_leaf over 398 days', 'build_leaf', { cn: 'A', root_cn: 'A', root_pkcs8: rootPkcs8, host_spki: hostSpki, endpoint: ENDPOINT, not_before: '2026-09-01T00:00:00Z', not_after: '2027-11-01T00:00:00Z', serial: SERIAL });
  // §14.1's ceiling at its edge, read from contract/contract.json's `Windows`: exactly max_leaf_days is
  // a leaf, and one second more is not. No case put a leaf there (C15's residual), so either port's
  // bound could have moved by a day unseen.
  const days = f.defs.Windows.const.max_leaf_days;
  const lasting = (s) => new Date(Date.parse('2026-09-01T00:00:00Z') + s * 1000).toISOString().replace('.000Z', 'Z');
  // The serial is given and the root is Ed25519, so the leaf is compared whole, byte for byte.
  for (const [what, seconds] of [[`exactly ${days} days`, days * 86400], [`${days} days and a second`, days * 86400 + 1]]) {
    add(`build_leaf of ${what}`, 'build_leaf', { cn: 'A', root_cn: 'A', root_pkcs8: rootPkcs8, host_spki: hostSpki, endpoint: ENDPOINT, not_before: '2026-09-01T00:00:00Z', not_after: lasting(seconds), serial: SERIAL });
  }
  expect(`build_leaf of ${days} days and a second`, { error: 'bad_request', why: 'validity over 398 days' });
  add('build_leaf backwards in time', 'build_leaf', { cn: 'A', root_cn: 'A', root_pkcs8: rootPkcs8, host_spki: hostSpki, endpoint: ENDPOINT, not_before: '2027-09-01T00:00:00Z', not_after: '2026-09-01T00:00:00Z', serial: SERIAL });
  for (const url of ['https://127.0.0.1/mcp', 'http://a.example/x', 'https://a.example/x/'])
    add(`build_leaf naming ${url}`, 'build_leaf', { cn: 'A', root_cn: 'A', root_pkcs8: rootPkcs8, host_spki: hostSpki, endpoint: url, not_before: now, not_after: '2027-09-01T00:00:00Z', serial: SERIAL });
  // The HAPPY PATH first, and it was missing: every case below is a refusal, so until the
  // `provenWhole` gate learned to read `ok: false` (2026-09-20) the six chain rules had never had a
  // SUCCESSFUL answer compared between the ports. `leaf_spki`, `leaf_fingerprint`, `root_fingerprint`
  // and `endpoint` are what a caller pins on, and a member dropped from any of them was invisible.
  add('validate_chain of a real chain', 'validate_chain', { chain: [leafDer, rootDer], now });
  add('validate_chain against the root and endpoint it really has', 'validate_chain', { chain: [leafDer, rootDer], now, expected_root: rootFp, expected_endpoint: ENDPOINT });

  // ── SPEC 2.1.1: the three rules added to the profile on 2026-09-20, held across the ports ─────────
  //
  // A P-256-rooted identity, because the first rule is about ECDSA and every other fixture here is
  // Ed25519 — which is how a port could have lacked the rule entirely with this harness green.
  add('validate_chain of a P-256 chain', 'validate_chain', { chain: [p256Leaf(), p256RootDer], now });
  add('validate_chain of a leaf whose ECDSA signature is the high twin', 'validate_chain', { chain: [twinLeaf, p256RootDer], now });
  add('parse_certificate of that leaf', 'parse_certificate', { der: twinLeaf }, (a) => ({ profile_error: a.profile_error, kind: a.kind }));
  add('profile_error of that leaf', 'profile_error', { der: twinLeaf, kind: 'leaf' });
  // The external-signing seam normalises: a token's high-S signature goes in, the low-S certificate
  // comes out, and it is the SAME certificate from both ports. (The plan is port-built: the seed has
  // no to-be-signed certificate.)
  {
    const plan = f.wasm.call('leaf_tbs', { cn: bharat.cn, root_cn: bharat.cn, root_spki: p256Spki, host_spki: hostSpki, endpoint: ENDPOINT, not_before: now, not_after: '2027-09-01T00:00:00Z', serial: b64url(new Uint8Array(8).fill(0x51)) });
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
    const strictLeaf = (misencode) => alinaLeaf({ label: 'parity/strict', misencode });
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
      const root = b64url(buildRoot({ cn: 'Alina Rao', key: rootKey, notBefore: BORN, label: 'parity/root', basicConstraints: bc }));
      add(`validate_chain under a root whose basicConstraints is ${what}`, 'validate_chain', { chain: [leafDer, root], now });
      add(`parse_certificate of a root whose basicConstraints is ${what}`, 'parse_certificate', { der: root });
    }
  }
  // What the seed's `parse` makes of a certificate, as parse_certificate answers it: the words it
  // refuses in (`unsupported` for a key outside the profile, CONTRACT §0; `parse` for the rest), or,
  // when it reads it, the certificate's key, beside what else the case expects of a certificate that
  // reads (`also`).
  const seedReads = (der, also = {}) => {
    try {
      return { ...also, spki: b64url(seedParse(Buffer.from(der, 'base64url')).spki) };
    } catch (e) {
      return { error: /^unsupported key type /.test(e.message) ? 'unsupported' : 'parse', why: e.message };
    }
  };
  // R33: certificates the three readers answered three ways. An empty keyUsage BIT STRING (`03 00`, no
  // initial octet, which X.690 §8.6.2 requires) was a keyUsage of no bits to the core and the seed and
  // refused by the Go port; an empty [3] was `not a v3 certificate with extensions` to the core and
  // `certificate shape` to the Go port (the seed threw a TypeError); and the two ports read a
  // certificate's fields in different orders, so one with two faults was named for different ones.
  // Built by hand from the leaf, which parse_certificate does not verify the signature of.
  {
    const parseFails = (why) => ({ error: 'parse', why });
    const [tbs, alg, sig] = derChildren(derRead(Buffer.from(leafDer, 'base64url')));
    const fields = derChildren(tbs).map((x) => x.raw);
    const [notBefore, notAfter] = derChildren(derChildren(tbs)[4]).map((x) => x.raw);
    const [algOid] = derChildren(alg).map((x) => x.raw);
    const NULL = Buffer.from([0x05, 0x00]);
    const rebuilt = (over, outer = alg.raw) => b64url(seq(seq(...fields.map((x, i) => over[i] ?? x)), outer, sig.raw));
    // keyUsage, critical: the extension with a padded OID (2.5.29.15 as 55 80 1d 0f) and a criticality
    // spelled 0x01, both faults; the core judges the criticality first.
    const [extensions] = derChildren(derChildren(tbs)[7]);
    const withBadKeyUsage = derChildren(extensions).map((e) => {
      const [id, , value] = derChildren(e);
      return id.content.equals(Buffer.from([0x55, 0x1d, 0x0f])) ? seq(tlv(0x06, Buffer.from([0x55, 0x80, 0x1d, 0x0f])), tlv(0x01, Buffer.from([0x01])), value.raw) : e.raw;
    });
    // Where the seed and the ports read a certificate's fields in one order — a single fault — the
    // answer expected is the SEED's (seedReads): its words, or the key it read. So the gate fails while
    // the seed beside it disagrees with the ports, which it did on pact-protocol main for the first
    // three (R33's seed half: an empty keyUsage and three validity times read, an empty [3] threw a
    // TypeError) until pact-protocol PR #10. The two with a fault in the outer algorithm are still read
    // in another order by the seed (`signature algorithm inside and outside differ`), and are held to
    // the ports' words.
    for (const [what, der, want] of [
      ['a keyUsage BIT STRING with no initial octet', alinaLeaf({ label: 'parity/r33', misencode: { keyUsage: [] } }), seedReads],
      ['an extensions wrapper with nothing in it', rebuilt({ 7: tlv(0xa3, Buffer.alloc(0)) }), seedReads],
      ['three validity times', rebuilt({ 4: seq(notBefore, notAfter, notAfter) }), seedReads],
      ['three validity times, and a NULL after the outer algorithm', rebuilt({ 4: seq(notBefore, notAfter, notAfter) }, seq(algOid, NULL)), parseFails('time not in the DER form')],
      ['a NULL after the outer algorithm', rebuilt({}, seq(algOid, NULL)), parseFails('certificate shape')],
      ['a keyUsage whose OID is padded and whose criticality is spelled 0x01', rebuilt({ 7: tlv(0xa3, seq(...withBadKeyUsage)) }), seedReads],
      // The controls: a keyUsage of no bits written with its initial octet (`03 01 00`) reads, and the
      // leaf rebuilt with nothing changed reads as the leaf — to the seed too.
      ['a keyUsage of no bits, with its initial octet', alinaLeaf({ label: 'parity/r33', misencode: { keyUsage: [0] } }), seedReads, { key_usage: [] }],
      ['nothing changed (the control)', rebuilt({}), seedReads, { spki: hostSpki }],
    ].map(([what, der, want, also = {}]) => [what, der, want === seedReads ? seedReads(der, also) : want])) {
      add(`parse_certificate of a leaf with ${what}`, 'parse_certificate', { der });
      expect(`parse_certificate of a leaf with ${what}`, want);
    }
  }
  // A validity field that is not a date, which one port used to read as 2 March.
  add('validate_chain of a leaf dated 30 February', 'validate_chain', { chain: [alinaLeaf({ notBefore: new Date('2026-03-02T12:00:00Z'), notAfter: new Date('2027-03-01T00:00:00Z'), label: 'parity/feb30', misencode: { notBefore: '260230120000Z' } }), rootDer], now });
  // An extension whose OID has an arc over 128 bits: 2.5.29.(2^128 + 17). One port accumulated arcs in
  // a u128 and read this as 2.5.29.17 — subjectAltName — and parsed it as one.
  add('parse_certificate of a leaf with a 129-bit OID arc', 'parse_certificate', { der: alinaLeaf({ label: 'parity/bigoid', extra: [{ oid: '2.5.29.' + (2n ** 128n + 17n).toString(), critical: false, value: Buffer.from([0x30, 0x00]) }] }) });
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
  add('assemble_leaf with a sig_alg that is not the TBS\'s', 'assemble_leaf', { tbs: leafTbs.tbs, sig: b64url(new Uint8Array(64)), sig_alg: b64url(new Uint8Array([0x30, 0x03, 0x06, 0x01, 0x2a])) });
  add('assemble_leaf with no signature', 'assemble_leaf', { tbs: leafTbs.tbs });
  add('assemble_root of a TBS that is not one', 'assemble_root', { tbs: b64url(new Uint8Array(4)), sig: b64url(new Uint8Array(64)) });

  // Every member that is absent rather than empty, and present as `null`.
  for (const [fn, args] of [
    ['parse_certificate', {}], ['profile_error', {}], ['compare_leaves', {}], ['is_normal_https', {}],
    ['address_guard', {}], ['ip_is_private', {}], ['validate_chain', { now }],
    ['build_root', { cn: 'A', not_before: now }], ['assemble_root', {}], ['assemble_leaf', {}],
  ]) add(`${fn} with nothing to work from`, fn, args);
  for (const [fn, k] of [['parse_certificate', 'der'], ['compare_leaves', 'pinned']]) add(`${fn} with ${k} as null`, fn, { [k]: null, presented: leafDer, now });
  add('validate_chain with chain as null', 'validate_chain', { chain: null, now });

  // ── one succeeding, whole-answer case per function ─────────────────────────────────────────────
  add('profile_error of a leaf read as a leaf', 'profile_error', { der: leafDer, kind: 'leaf' });
  add('profile_error of a root read as a root', 'profile_error', { der: rootDer, kind: 'root' });
  // The external-signing seam, end to end: the core makes the bytes (port-built: the seed has no
  // TBS), the seed signs, the core assembles — and the certificate it assembles is the other port's.
  add('assemble_root', 'assemble_root', { tbs: rootTbs.tbs, sig_alg: rootTbs.sig_alg, sig: b64url(signDetached(rootKey.priv, Buffer.from(rootTbs.tbs, 'base64url'))) });
  add('assemble_leaf', 'assemble_leaf', { tbs: leafTbs.tbs, sig_alg: leafTbs.sig_alg, sig: b64url(signDetached(rootKey.priv, Buffer.from(leafTbs.tbs, 'base64url'))) });

  // A member that is ABSENT is `<name> is required` and `bad_request`, whatever its type. For an
  // instant the Go port said "an instant is required" and called it `parse` — in every function that
  // takes one — and no case here had ever left `now` out.
  add('validate_chain with no now', 'validate_chain', { chain: [leafDer, rootDer] });
  add('build_leaf with no not_before', 'build_leaf', { cn: 'Alina Rao', root_cn: 'Alina Rao', root_pkcs8: rootPkcs8, host_spki: hostSpki, endpoint: ENDPOINT, not_after: '2027-09-01T00:00:00Z' });
  add('validate_chain with a now that is there and is not an instant', 'validate_chain', { chain: [leafDer, rootDer], now: 'soon' });
  add('validate_chain with a now that is empty', 'validate_chain', { chain: [leafDer, rootDer], now: '' });

  // ── C: what reached the pinned core. Both ports were wrong the SAME way on most of these, so parity
  // could not have seen them; each port's own tests were red first, and these hold the two together.
  add('parse_certificate of a leaf naming its issuer in three bytes', 'parse_certificate', { der: shortAki });
  add('validate_chain of a leaf naming its issuer in three bytes', 'validate_chain', { chain: [shortAki, rootDer], now });
  for (const ip of ['64:ff9b::7f00:1', '64:ff9b::a9fe:a9fe', '64:ff9b::808:808', '64:ff9b:1::1', '2002:7f00:1::1', '2002:808:808::1', 'fec0::1', '::7f00:1', '::808:808', '2606:4700:4700::1111', '::ffff:127.0.0.1', '::1', '::'])
    add(`ip_is_private ${ip}`, 'ip_is_private', { ip });
  for (const endpoint of ['https://[64:ff9b::7f00:1]/mcp', 'https://[2002:c0a8:101::1]/mcp', 'https://[64:ff9b::808:808]/mcp', 'https://[2606:4700:4700::1111]/mcp'])
    add(`address_guard ${endpoint}`, 'address_guard', { endpoint, guest: true });
  const E8443 = 'https://agent.alina.example:8443/mcp';
  const leaf8443 = alinaLeaf({ endpoint: E8443, dnsName: 'agent.alina.example', label: 'parity/8443' });
  add('validate_chain of a leaf on another port carrying its host\'s dNSName', 'validate_chain', { chain: [leaf8443, rootDer], now, expected_endpoint: E8443 });

  // B7 — `now` is whole seconds. Half a second past a leaf's notAfter is the same second.
  add('validate_chain half a second after the leaf\'s last second', 'validate_chain', { chain: [leafDer, rootDer], now: '2027-09-01T00:00:00.500Z', expected_root: rootFp, expected_endpoint: ENDPOINT });
  add('validate_chain in the leaf\'s last second, with a fraction', 'validate_chain', { chain: [leafDer, rootDer], now: '2027-08-31T23:59:59.900Z', expected_root: rootFp, expected_endpoint: ENDPOINT });
  // Half a surrogate pair refused at the boundary, and a whole pair, which is text, reaching the rule.
  add('is_normal_https with args holding a lone low surrogate', 'is_normal_https', { url: 'https://x.example/\udc00' });
  expect('is_normal_https with args holding a lone low surrogate', { error: 'bad_request', why: 'args: a string holds half of a UTF-16 surrogate pair' });
  add('is_normal_https with args holding a surrogate pair', 'is_normal_https', { url: 'https://x.example/\ud83d\ude00' });
  // A member named exactly: the Go port's struct decoding matched members without regard to case, so
  // `CN` filled `cn` there and a root was built for a member the Rust core never read.
  add('build_root with CN, not cn', 'build_root', { CN: 'Mallory' });
  expect('build_root with CN, not cn', { error: 'bad_request', why: 'build_root takes no member "CN"' });
  // An empty string is a value, not an absent member (CONTRACT §0; F4, R07, T14): an expectation
  // given as "" is compared and refused, as the core compares it. The Go port read it as "not given"
  // at the boundary; its typed ChainOpts still do, for a Go caller (the node) that means that by it.
  add('validate_chain with an expected_root that is empty', 'validate_chain', { chain: [leafDer, rootDer], now, expected_root: '', expected_endpoint: ENDPOINT });
  expect('validate_chain with an expected_root that is empty', { ok: false, rule: 2, reason: 'root is not the one expected' });
  add('validate_chain with an expected_endpoint that is empty', 'validate_chain', { chain: [leafDer, rootDer], now, expected_root: rootFp, expected_endpoint: '' });
  expect('validate_chain with an expected_endpoint that is empty', { ok: false, rule: 5, reason: 'endpoint differs from the one in question' });
  // A dns_name given as "" names no host, and is refused where it is read (R26, F4): the core wrote an
  // empty dNSName, which rule 5 then refused, and the Go port wrote none.
  add('build_leaf with a dns_name that is empty', 'build_leaf', { cn: 'Alina Rao', root_cn: 'Alina Rao', root_pkcs8: rootPkcs8, host_spki: hostSpki, endpoint: ENDPOINT, dns_name: '', not_before: now, not_after: '2027-09-01T00:00:00Z', serial: SERIAL });
  expect('build_leaf with a dns_name that is empty', { error: 'bad_request', why: 'dns_name is empty' });

  // ── F: a zone id in an IPv6 literal (T1, C1, R09, R10, F15) ──────────────────────────────────────
  //
  // §14.1's normal form is RFC 3986's, which has no zone in an IPv6 literal, and the seed's
  // isNormalHttps parses with WHATWG's URL, which refuses a `%` inside the brackets. The Go port
  // read the literal with netip, which takes any zone after `%` — `%eth0`, `%25eth0`, and
  // `%x@evil.example`, `%x?y` and `%x#y`, whose `@`, `?` and `#` its own doc comment says the normal
  // form never holds — so a zoned global address was normal https and passed the address guard there,
  // and a zoned private one was refused for a different reason, where the core refused every one as
  // not the normal form.
  for (const url of ZONED) {
    add(`is_normal_https with a zone id: ${url}`, 'is_normal_https', { url });
    expect(`is_normal_https with a zone id: ${url}`, { normal: false });
    add(`address_guard with a zone id: ${url}`, 'address_guard', { endpoint: url, guest: true });
    expect(`address_guard with a zone id: ${url}`, { ok: false, why: 'endpoint is not an https URL in normal form' });
  }
  for (const endpoint of ZONED.slice(0, 2)) {
    const zonedLeaf = alinaLeaf({ endpoint, label: `parity/zone/${endpoint}` });
    add(`validate_chain of a leaf naming ${endpoint}`, 'validate_chain', { chain: [zonedLeaf, rootDer], now });
    expect(`validate_chain of a leaf naming ${endpoint}`, { ok: false, rule: 5, reason: 'endpoint is not an https URL in normal form' });
    add(`build_leaf naming ${endpoint}`, 'build_leaf', { cn: 'A', root_cn: 'A', root_pkcs8: rootPkcs8, host_spki: hostSpki, endpoint, not_before: now, not_after: '2027-09-01T00:00:00Z', serial: SERIAL });
    expect(`build_leaf naming ${endpoint}`, { error: 'bad_request', why: 'endpoint is not an https URL in normal form' });
    add(`leaf_tbs naming ${endpoint}`, 'leaf_tbs', { cn: 'A', root_cn: 'A', root_spki: rootSpki, host_spki: hostSpki, endpoint, not_before: now, not_after: '2027-09-01T00:00:00Z', serial: SERIAL });
    expect(`leaf_tbs naming ${endpoint}`, { error: 'bad_request', why: 'endpoint is not an https URL in normal form' });
  }
  // ip_is_private has no URL around it, so it cannot lean on the normal form: the rule is its own. A
  // zone is RFC 4007's interface scope, which a global address never carries (§6), so an IPv6 literal
  // with one is never a public address: private, in both ports, the core included (it could not parse
  // one, and answered false — a resolver's `fe80::1%eth0` was public to it). netip's reading of the
  // text is kept: an empty zone, or a zone on an IPv4 address, is no address at all.
  for (const [ip, isPrivate] of [
    ['fe80::1%eth0', true], ['2001:db8::1%eth0', true], ['[fe80::1%eth0]', true], ['::ffff:10.0.0.1%eth0', true],
    ['2606:4700:4700::1111%25eth0', true], ['fe80::1%eth0%x', true], ['fe80::1%', false], ['10.0.0.1%eth0', false], ['8.8.8.8%eth0', false],
  ]) {
    add(`ip_is_private with a zone id: ${ip}`, 'ip_is_private', { ip });
    expect(`ip_is_private with a zone id: ${ip}`, { private: isPrivate });
  }
  // R11: one pair of brackets is an IPv6 literal's spelling; a second pair is not an address. The core
  // stripped every bracket from both ends and the Go port one from each.
  for (const [ip, isPrivate] of [['[[::1]]', false], [']::1[', false], ['[[10.0.0.1]]', false], ['[::1', true], ['::1]', true], ['[10.0.0.1]', true], ['[8.8.8.8]', false]]) {
    add(`ip_is_private in brackets: ${ip}`, 'ip_is_private', { ip });
    expect(`ip_is_private in brackets: ${ip}`, { private: isPrivate });
  }

  // ── G: a key outside the profile (R12, T2, R13, R35) ─────────────────────────────────────────────
  //
  // A certificate carrying one does not read, in either port, and names the key: the Go port parsed
  // it with an `alg` of "" (or `x25519`), which the contract's Alg does not have, and judged it at the
  // profile, so compare_leaves compared it and parse_certificate answered it. And a key that is not a
  // signing key's algorithm signs nothing: the Go port declared ECDSA for an X25519 root key (R13).
  for (const [kind, { spki, oid }] of Object.entries(f.foreign)) {
    const why = `unsupported key type ${oid}`, refused = { error: 'unsupported', why };
    const leaf = f.foreignLeaf(kind);
    add(`parse_certificate of a leaf holding a key outside the profile: ${kind}`, 'parse_certificate', { der: leaf });
    // Held to the seed's reading (seedReads), which read all four keys on pact-protocol main until
    // PR #10 (cluster G's seed half).
    expect(`parse_certificate of a leaf holding a key outside the profile: ${kind}`, seedReads(leaf));
    add(`profile_error of a leaf holding a key outside the profile: ${kind}`, 'profile_error', { der: leaf, kind: 'leaf' });
    expect(`profile_error of a leaf holding a key outside the profile: ${kind}`, refused);
    add(`validate_chain of a leaf holding a key outside the profile: ${kind}`, 'validate_chain', { chain: [leaf, rootDer], now });
    expect(`validate_chain of a leaf holding a key outside the profile: ${kind}`, { ok: false, rule: 1, reason: why });
    add(`compare_leaves against a leaf holding a key outside the profile: ${kind}`, 'compare_leaves', { pinned: leafDer, presented: leaf });
    expect(`compare_leaves against a leaf holding a key outside the profile: ${kind}`, refused);
    add(`root_tbs of a key outside the profile: ${kind}`, 'root_tbs', { cn: 'Alina Rao', spki: b64url(spki), not_before: now, serial: SERIAL });
    expect(`root_tbs of a key outside the profile: ${kind}`, refused);
    add(`leaf_tbs under a root key outside the profile: ${kind}`, 'leaf_tbs', { cn: 'A', root_cn: 'A', root_spki: b64url(spki), host_spki: hostSpki, endpoint: ENDPOINT, not_before: now, not_after: '2027-09-01T00:00:00Z', serial: SERIAL });
    expect(`leaf_tbs under a root key outside the profile: ${kind}`, refused);
    add(`build_leaf for a host key outside the profile: ${kind}`, 'build_leaf', { cn: 'A', root_cn: 'A', root_pkcs8: rootPkcs8, host_spki: b64url(spki), endpoint: ENDPOINT, not_before: now, not_after: '2027-09-01T00:00:00Z', serial: SERIAL });
    expect(`build_leaf for a host key outside the profile: ${kind}`, refused);
  }

  // A leaf whose Ed25519 key is 32 bytes that decode to no point (S4-1): refused at rule 1 by the core,
  // and validated by the Go port, which read it as a key. Written by the seed, which reads no key here.
  const notAPoint = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from([2]), Buffer.alloc(31)]);
  const notAPointLeaf = alinaLeaf({ hostKey: { pub: { export: () => notAPoint } }, usage: [0], label: 'parity/not-a-point' });
  add('validate_chain of a leaf whose Ed25519 key is not a point', 'validate_chain', { chain: [notAPointLeaf, rootDer], now });
  expect('validate_chain of a leaf whose Ed25519 key is not a point', { ok: false, rule: 1, reason: 'Ed25519 key is not a point' });
  add('parse_certificate of a leaf whose Ed25519 key is not a point', 'parse_certificate', { der: notAPointLeaf });
  expect('parse_certificate of a leaf whose Ed25519 key is not a point', { error: 'parse', why: 'Ed25519 key is not a point' });

  // A CA certificate is judged as a root only when it is also self-issued, and otherwise as a leaf
  // (contract/contract.json `Certificate`): the Go port judged every CA as a root, so a CA-flagged
  // leaf under another name was 'root extensions are not exactly the profile' there and 'leaf
  // basicConstraints' in the core (T17). Built by the seed, whose `buildLeaf` still takes the CA
  // flag no port's boundary does; the verdict expected is the seed's own judge, under the contract's
  // rule, so it is neither port's answer. Both sides of the rule: another name, and its own.
  for (const [what, o] of [
    ['whose issuer is not its subject', { cn: 'Alina Rao (host)', cA: true, label: 'parity/ca-leaf' }],
    ['whose issuer is its subject', { cA: true, label: 'parity/ca-leaf-self' }],
  ]) {
    const der = alinaLeaf(o);
    const c = seedParse(Buffer.from(der, 'base64url'));
    const as = c.issuer === c.subject && c.ca ? 'root' : 'leaf';
    add(`parse_certificate of a CA certificate ${what}`, 'parse_certificate', { der });
    expect(`parse_certificate of a CA certificate ${what}`, { kind: 'other', ca: true, profile_error: seedProfileError(c, as) });
  }
}
