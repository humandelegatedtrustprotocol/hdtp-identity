// §5 of the contract: envelopes — the suite, HPKE, sealing and opening, following a renewal, and the
// receiving decision.
import { seed, b64url } from '../../../pact-protocol/vectors/lib/keys.mjs';
import { buildLeaf } from '../../../pact-protocol/vectors/lib/x509.mjs';
import { sealDeterministic } from '../../../pact-protocol/vectors/lib/hpke.mjs';
import { ENDPOINTS } from '../cast.mjs';

export default function envelopes({ add, expect }, f) {
  const { now, at, ENDPOINT, rootKey, hostKey, rootDer, leafDer, rootPkcs8, hostPkcs8, rootSpki, hostSpki, p256Spki, rsaSpki, rootFp, hostFp } = f;
  const { request, sealed, sealedNoTool, small, node, pinned, open, chainForm, leafForm, answerTo, follow, olderLeaf } = f;
  const eph = (n) => b64url(new Uint8Array(32).fill(n));

  add('suite_for an spki that is not one', 'suite_for', { spki: b64url(new Uint8Array(4)) });
  add('suite_for an Ed25519 key', 'suite_for', { spki: hostSpki });
  add('suite_for a P-256 key', 'suite_for', { spki: p256Spki });
  add('suite_for an RSA key', 'suite_for', { spki: rsaSpki });
  add('seal_request with no recipient', 'seal_request', { sender_pkcs8: hostPkcs8, form: 'chain', method: 'tools/call', params: {}, msg_id: 'x', ts: 1, ephemeral_seed: eph(7) });
  add('seal_request with a form nobody has', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'sideways', method: 'tools/call', params: {}, msg_id: 'x', ts: 1, ephemeral_seed: eph(7) });
  add('seal_request with a method nobody has', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/dance', params: {}, msg_id: 'x', ts: 1, ephemeral_seed: eph(7) });
  add('seal_request with an empty msg_id', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: {}, msg_id: '', ts: 1, ephemeral_seed: eph(7) });
  add('seal_request whose exp is a month past its ts', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: {}, msg_id: 'x', ts: 1, exp: 1 + 31 * 86400, ephemeral_seed: eph(7) });
  add('hpke_open of a ciphertext that is not one', 'hpke_open', { suite: 'PACT-SEAL-X25519', recipient_pkcs8: hostPkcs8, recipient_spki: hostSpki, info: 'PACT-SEAL-v2', aad: '', enc: b64url(new Uint8Array(32)), ct: b64url(new Uint8Array(32)) });
  add('hpke_seal with a suite nobody has', 'hpke_seal', { suite: 'PACT-SEAL-ROT13', recipient_spki: hostSpki, info: 'x', aad: '', plaintext: '' });
  // `decide`'s refusal lives in `result.code`, not in a top-level `error`, so it too was once counted
  // as proven whole on a success it had never given. This is the one that reaches the contact tier,
  // where `tier`, `root`, `endpoint`, `method`, `form`, `params`, `leaf` and `effects` are all
  // populated and comparable.
  add('decide on an envelope from a pinned contact', 'decide', { now, envelope: sealed, node: { ...node, pins: pinned } });
  // A call that names no tool, from a pinned contact: the answer's `tool` member is the one the Go
  // port omitted and the Rust core set to null.
  add('decide on a pinned contact\'s call that names no tool', 'decide', { now, envelope: sealedNoTool, node: { ...node, pins: pinned } });
  add('decide on an envelope for a key nobody holds', 'decide', { now, envelope: sealed, node: { ...node, keys: [] } });
  add('decide on a real envelope from a stranger', 'decide', { now, envelope: sealed, node });
  add('decide on an envelope whose signature is wrong', 'decide', { now, envelope: { ...sealed, sig: b64url(new Uint8Array(64)) }, node });
  add('decide on a header that is not JSON', 'decide', { now, envelope: { ...sealed, protected: b64url(new Uint8Array([1, 2, 3])) }, node });
  add('decide with no node at all', 'decide', { now, envelope: sealed });
  add('decide on an envelope long past its exp', 'decide', { now: '2027-01-01T00:00:00Z', envelope: sealed, node });
  // An `exp` of 2^41 — past any plausible year. A first fix for an i64 wrap bounded the timestamps to a
  // band before the arithmetic, and so answered "outside the time window" here where the other port
  // answers "exp too far from ts": a divergence introduced by the fix for one. Exact arithmetic now.
  add('decide on an envelope whose exp is in the year 71,000', 'decide', { now, envelope: request({ params: { name: 'send_message' }, msgId: 'parity-far', exp: 2 ** 41, ephemeralSeed: Buffer.alloc(32, 6) }), node });
  add('open_result of a request envelope', 'open_result', { envelope: sealed, my_pkcs8: hostPkcs8, my_spki: hostSpki, msg_id: 'p-1', now, pins: [] });
  add('follow_renewed on a chain to another root', 'follow_renewed', { answer: { code: 'certificate_renewed', data: { chain: [leafDer, rootDer] } }, pinned_root: 'sha256:' + 'A'.repeat(43), pinned_leaf: leafDer, dialed: ENDPOINT, now });
  add('follow_renewed on a chain that is not one', 'follow_renewed', { answer: { code: 'certificate_renewed', data: { chain: [] } }, pinned_root: rootFp, pinned_leaf: leafDer, dialed: ENDPOINT, now });
  add('follow_renewed on the same leaf', 'follow_renewed', { answer: { code: 'certificate_renewed', data: { chain: [leafDer, rootDer] } }, pinned_root: rootFp, pinned_leaf: leafDer, dialed: ENDPOINT, now });

  // A request the seed can make and both ports must answer identically: the header carries the rules.
  add('seal_request', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: { name: 'send_message' }, msg_id: 'p-2', ts: at(now), ephemeral_seed: eph(7) });
  add('seal_request with no msg_id at all', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: {}, ts: 1, ephemeral_seed: eph(7) });
  add('seal_request with an ephemeral_seed, which neither port takes', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: {}, msg_id: 'x', ts: 1, ephemeral_seed: b64url(new Uint8Array(32)) });
  add('seal_result', 'seal_result', { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, result: { ok: true }, msg_id: 'p-1', ts: at(now), ephemeral_seed: eph(7) });
  add('seal_result with no recipient', 'seal_result', { sender_pkcs8: hostPkcs8, result: {}, msg_id: 'x', ts: 1, ephemeral_seed: eph(7) });
  add('seal_result with neither a result nor an error', 'seal_result', { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, msg_id: 'x', ts: 1, ephemeral_seed: eph(7) });

  // Every member that is absent rather than empty. A sealed answer carries a fresh ephemeral, so the
  // two seal_ functions are compared on the members that do not move.
  for (const [fn, args] of [
    ['suite_for', {}], ['hpke_seal', {}], ['hpke_open', {}], ['seal_request', {}], ['seal_result', {}],
    ['open_result', {}], ['follow_renewed', {}], ['decide', { now }],
  ]) add(`${fn} with nothing to work from`, fn, args, fn.startsWith('seal_') ? ['error', 'why', 'protected'] : '*');

  // ── one succeeding, whole-answer case per function ─────────────────────────────────────────────
  // HPKE with a fixed ephemeral is reproducible, which is what makes it comparable at all.
  const hpkeArgs = { suite: 'PACT-SEAL-X25519', recipient_spki: hostSpki, info: 'PACT-SEAL-v2', aad: b64url(new Uint8Array([9])), plaintext: b64url(new Uint8Array([1, 2, 3])), ephemeral_seed: eph(5) };
  add('hpke_seal', 'hpke_seal', hpkeArgs);
  // The seal the case above asks for, made by the seed from the same ephemeral seed.
  const sealedHpke = sealDeterministic('PACT-SEAL-X25519', hostKey.pub, Buffer.from('PACT-SEAL-v2'), Buffer.from([9]), Buffer.from([1, 2, 3]), Buffer.alloc(32, 5));
  add('hpke_open of what hpke_seal made', 'hpke_open', { suite: 'PACT-SEAL-X25519', recipient_pkcs8: hostPkcs8, recipient_spki: hostSpki, info: 'PACT-SEAL-v2', aad: b64url(new Uint8Array([9])), enc: b64url(sealedHpke.enc), ct: b64url(sealedHpke.ct) });
  // A result sealed and opened: the one path a caller reads members other than `ok` from. Port-built:
  // the seed seals requests, not results.
  const resultArgs = { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], result: { ok: true, items: [1, 2] }, msg_id: 'p-1', ts: at(now), ephemeral_seed: eph(5) };
  add('seal_result of a real result', 'seal_result', resultArgs);
  add('open_result of what seal_result made', 'open_result', { envelope: f.wasm.call('seal_result', resultArgs), my_pkcs8: hostPkcs8, my_spki: hostSpki, msg_id: 'p-1', now, pins: [] });

  // ── 2026-09-28: the recipient's public key is handed in, never derived from its private key ────
  // A public key that is not the private key's must refuse, never yield a plaintext.
  const hpkeOpen = { suite: 'PACT-SEAL-X25519', recipient_pkcs8: hostPkcs8, recipient_spki: hostSpki, info: 'PACT-SEAL-v2', aad: b64url(new Uint8Array([9])), enc: b64url(sealedHpke.enc), ct: b64url(sealedHpke.ct) };
  add('hpke_open with a public key that is another Ed25519 key', 'hpke_open', { ...hpkeOpen, recipient_spki: rootSpki });
  expect('hpke_open with a public key that is another Ed25519 key', { error: 'envelope_invalid', why: 'does not open' });
  add('hpke_open with a public key of the other algorithm', 'hpke_open', { ...hpkeOpen, recipient_spki: p256Spki });
  expect('hpke_open with a public key of the other algorithm', { error: 'envelope_invalid', why: 'does not open' });
  add('hpke_open with no public key', 'hpke_open', { ...hpkeOpen, recipient_spki: undefined });
  expect('hpke_open with no public key', { error: 'bad_request', why: 'recipient_spki is required' });
  const sealedResult = f.wasm.call('seal_result', resultArgs);
  add('open_result with a public key that is not this key\'s: the kid says so first', 'open_result', { envelope: sealedResult, my_pkcs8: hostPkcs8, my_spki: rootSpki, msg_id: 'p-1', now, pins: [] });
  expect('open_result with a public key that is not this key\'s: the kid says so first', { error: 'envelope_invalid', why: 'kid is not this key' });
  add('open_result with the kid\'s public key and another private key: it does not open', 'open_result', { envelope: sealedResult, my_pkcs8: rootPkcs8, my_spki: hostSpki, msg_id: 'p-1', now, pins: [] });
  expect('open_result with the kid\'s public key and another private key: it does not open', { error: 'envelope_invalid', why: 'does not open' });
  add('open_result with no public key', 'open_result', { envelope: sealedResult, my_pkcs8: hostPkcs8, msg_id: 'p-1', now, pins: [] });
  expect('open_result with no public key', { error: 'bad_request', why: 'my_spki is required' });

  // ── 2026-09-21: what the Go port answered differently (review-findings plan, B) ────────────────
  //
  // Each of these was RED against the Go port before the port was changed, and that is the only
  // reason to believe it looks at what it names.
  const reheader = (e, patch) => ({ ...e, protected: b64url(Buffer.from(JSON.stringify(Object.fromEntries(Object.entries({ ...JSON.parse(Buffer.from(e.protected, 'base64url').toString()), ...patch }).sort(([a], [b]) => (a < b ? -1 : 1)))))) });

  // B1 — OpenResult: Rust's words, and Rust's order.
  add('open_result with a key the envelope is not sealed to', 'open_result', open(chainForm, { my_pkcs8: rootPkcs8, my_spki: rootSpki }));
  add('open_result whose header names a suite that is known and is not this key\'s', 'open_result', open(reheader(chainForm, { suite: 'PACT-SEAL-P256' })));
  add('open_result with the wrong key AND the wrong suite: which is said first', 'open_result', open(reheader(chainForm, { suite: 'PACT-SEAL-P256' }), { my_pkcs8: rootPkcs8, my_spki: rootSpki }));
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
  // Sealed from a FIXED ephemeral seed. Which of the spellings below exist depends on the bytes — a
  // string with no `-` or `_` has no standard-alphabet twin — and `sealed` is new every run, so the
  // NUMBER of cases moved between runs (420, then 421) and PROOFS.md's count with it: a gate that goes
  // stale at random. These bytes are the same every time.
  const spelt = request({ params: { name: 'send_message' }, msgId: 'p-spelt', ephemeralSeed: seed('parity/spelt') });
  // The other spellings a forgiving reader takes: padding, the standard alphabet, whitespace. Both
  // ports forgave these in an envelope, consistently — and an envelope member has ONE spelling (§13.1).
  const pad = (s) => s + '='.repeat((4 - (s.length % 4)) % 4);
  const std = (s) => s.replace(/-/g, '+').replace(/_/g, '/');
  for (const member of ['protected', 'enc', 'ct', 'sig']) {
    if (pad(spelt[member]) !== spelt[member]) add(`decide on a real envelope whose ${member} is padded`, 'decide', { now, envelope: { ...spelt, [member]: pad(spelt[member]) }, node });
    if (std(spelt[member]) !== spelt[member]) add(`decide on a real envelope whose ${member} uses the standard alphabet`, 'decide', { now, envelope: { ...spelt, [member]: std(spelt[member]) }, node });
    add(`decide on a real envelope whose ${member} has a line break in it`, 'decide', { now, envelope: { ...spelt, [member]: `${spelt[member].slice(0, 8)}\n${spelt[member].slice(8)}` }, node });
    add(`decide on a real envelope whose ${member} has a space in it`, 'decide', { now, envelope: { ...spelt, [member]: `${spelt[member].slice(0, 8)} ${spelt[member].slice(8)}` }, node });
  }
  add('open_result on a real answer whose enc is padded', 'open_result', open({ ...chainForm, enc: pad(chainForm.enc) }));
  add('open_result on a real answer whose sig has a line break in it', 'open_result', open({ ...chainForm, sig: `${chainForm.sig.slice(0, 8)}\n${chainForm.sig.slice(8)}` }));
  for (const member of ['protected', 'enc', 'ct', 'sig']) {
    const again = respell(spelt[member]);
    if (again) add(`decide on a real envelope whose ${member} is spelled with its spare bits set`, 'decide', { now, envelope: { ...spelt, [member]: again }, node });
  }

  // B3 — the node's OWN state, unreadable. The seed throws; so does the core.
  add('decide when a held key\'s own leaf will not parse', 'decide', { now, envelope: sealed, node: { ...node, keys: [{ ...node.keys[0], leaf: '!!!' }] } });
  add('decide in the small form when a pin\'s leaf will not parse', 'decide', { now, envelope: small, node: { ...node, pins: [{ root: rootFp, endpoint: ENDPOINT, leaf: 'AAAA', state: 'active' }] } });
  add('decide when the pinned leaf of the sender\'s root will not compare', 'decide', { now, envelope: sealed, node: { ...node, pins: [{ root: rootFp, endpoint: ENDPOINT, leaf: 'AAAA', state: 'active' }] } });
  add('decide when a tombstone\'s instant will not parse', 'decide', { now, envelope: sealed, node: { ...node, tombstones: [{ root: rootFp, at: 'soon', leaf: olderLeaf }] } });
  add('decide when a tombstone\'s leaf will not compare', 'decide', { now, envelope: sealed, node: { ...node, tombstones: [{ root: rootFp, at: '2026-09-10T00:00:00Z', leaf: 'AAAA' }] } });
  add('decide with two tombstones for one root, the FIRST of them stale', 'decide', { now, envelope: sealed, node: { ...node, tombstones: [{ root: rootFp, at: '2026-01-01T00:00:00Z', leaf: olderLeaf }, { root: rootFp, at: '2026-09-10T00:00:00Z', leaf: olderLeaf }] } });
  add('decide on a peer who returns after removal: the answer that succeeds', 'decide', { now, envelope: sealed, node: { ...node, tombstones: [{ root: rootFp, at: '2026-09-10T00:00:00Z', leaf: olderLeaf }] } });

  // B4 — follow_renewed.
  add('follow_renewed on an answer that is some other code', 'follow_renewed', follow({ code: 'something_else' }));
  add('follow_renewed on a certificate_renewed answer with no data at all', 'follow_renewed', follow({ code: 'certificate_renewed' }));
  add('follow_renewed on a certificate_renewed answer whose data has no chain', 'follow_renewed', follow({ code: 'certificate_renewed', data: {} }));
  add('follow_renewed on a chain that is null', 'follow_renewed', follow({ code: 'certificate_renewed', data: { chain: null } }));
  add('follow_renewed on a chain that is not a list', 'follow_renewed', follow({ code: 'certificate_renewed', data: { chain: 'AAAA' } }));
  add('follow_renewed on a chain whose members are not base64url', 'follow_renewed', follow({ code: 'certificate_renewed', data: { chain: ['!!!', '!!!'] } }));
  add('follow_renewed on a chain of none', 'follow_renewed', follow({ code: 'certificate_renewed', data: { chain: [] } }));
  add('follow_renewed to a leaf OLDER than the one pinned', 'follow_renewed', follow({ code: 'certificate_renewed', data: { chain: [olderLeaf, rootDer] } }));

  // A member that is ABSENT is `<name> is required` and `bad_request`, whatever its type.
  add('decide with no now', 'decide', { envelope: sealed, node });
  add('open_result with no now', 'open_result', { ...open(chainForm), now: undefined });
  add('follow_renewed with no now', 'follow_renewed', { ...follow({ code: 'certificate_renewed', data: { chain: [leafDer, rootDer] } }), now: undefined });

  // C9 — a chain that is THERE and will not read is not a chain that was left out.
  const sealing = (o) => ({ recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', method: 'tools/call', params: {}, msg_id: 'c9', ts: at(now), ephemeral_seed: b64url(seed('parity/c9')), ...o });
  add('seal_request in the chain form with no sender_chain', 'seal_request', sealing({}));
  add('seal_request whose sender_chain is not base64url', 'seal_request', sealing({ sender_chain: ['!!!', '!!!'] }));
  add('seal_request whose sender_chain is not a list', 'seal_request', sealing({ sender_chain: 'AAAA' }));
  add('seal_result whose sender_chain is not base64url', 'seal_result', { recipient_spki: f.callerSpki, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: ['!!!'], result: {}, msg_id: 'c9', ts: at(now) });

  // C — the small form names its leaf, and an unreadable pin that names some OTHER leaf is never parsed.
  const mine = { root: rootFp, endpoint: ENDPOINT, leaf: leafDer, state: 'active' };
  const gone = { root: 'sha256:a-row-gone-bad', endpoint: 'https://ghost.example/mcp', leaf: 'AAAA', state: 'active' };
  add('decide, small form: the pin names its leaf', 'decide', { now, envelope: small, node: { ...node, pins: [{ ...mine, leaf_fingerprint: hostFp }] } });
  add('decide, small form: an unreadable pin that names some OTHER leaf is never parsed', 'decide', { now, envelope: small, node: { ...node, pins: [{ ...gone, leaf_fingerprint: 'sha256:somebody-else' }, { ...mine, leaf_fingerprint: hostFp }] } });
  add('decide, small form: an unreadable pin that names no leaf has to be parsed', 'decide', { now, envelope: small, node: { ...node, pins: [gone, { ...mine, leaf_fingerprint: hostFp }] } });
  add('decide, small form: a pin whose named leaf is not its leaf', 'decide', { now, envelope: small, node: { ...node, pins: [{ ...mine, leaf: rootDer, leaf_fingerprint: hostFp }] } });
  add('open_result, leaf form: the pin names its leaf', 'open_result', open(leafForm, { pins: [{ ...mine, leaf_fingerprint: hostFp }] }));
  add('open_result, leaf form: a pin whose named leaf is not its leaf', 'open_result', open(leafForm, { pins: [{ ...mine, leaf: rootDer, leaf_fingerprint: hostFp }] }));

  // ── P-21 (review of 2026-09-23): a pending contact's sealed listing ──────────────────────────────
  //
  // `tools/list` returns what the caller's tier may use (SPEC §6), and a sealed call is dispatched in
  // the tier the proven identity earns (§13.2). A listing names no tool, so both ports answered it
  // `pending_approval` at a `pending_out` pin, and agreed with each other doing it: a comparison of two
  // ports cannot see a rule both break. So these cases carry what the spec says the answer IS, and the
  // runner holds both ports to it — in the small form, the chain form, and the path where the pin
  // moves on the way through (§5.3 under `auto`). The controls are the calls that must still wait.
  const MOVED = ENDPOINTS.alinaMoved;
  const movedLeaf = buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: MOVED, notBefore: new Date('2026-09-10T00:00:00Z'), notAfter: new Date('2027-09-10T00:00:00Z'), label: 'parity/p21/moved' });
  const pendingOut = { ...node, pins: [{ root: rootFp, endpoint: ENDPOINT, leaf: leafDer, state: 'pending_out' }] };
  const seal = (form, chainLeaf, method, params) => request({ ...(form === 'chain' ? { senderChain: [chainLeaf, f.rootDerBytes] } : { reference: true }), method, params, msgId: 'p-21' });
  for (const [what, form, chainLeaf, endpoint] of [['small form', 'leaf', null, ENDPOINT], ['chain form', 'chain', f.leafDerBytes, ENDPOINT], ['chain form, the pin moving', 'chain', movedLeaf, MOVED]]) {
    const listing = `decide: a pending_out contact's sealed tools/list, ${what}`;
    add(listing, 'decide', { now, envelope: seal(form, chainLeaf, 'tools/list', {}), node: pendingOut });
    expect(listing, { code: 'ok', tier: 'pending', endpoint });
    const control = `decide: a pending_out contact's sealed send_message waits, ${what}`;
    add(control, 'decide', { now, envelope: seal(form, chainLeaf, 'tools/call', { name: 'send_message' }), node: pendingOut });
    expect(control, { code: 'pending_approval' });
  }
}
