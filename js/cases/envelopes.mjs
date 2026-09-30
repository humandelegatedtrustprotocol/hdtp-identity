// §5 of the contract: envelopes — the suite, HPKE, sealing and opening, following a renewal, and the
// receiving decision.
import { seed, b64url, pkcs8Of, spkiOf, fingerprint, x25519FromSeed } from '../../../pact-protocol/vectors/lib/keys.mjs';
import { buildLeaf, parse } from '../../../pact-protocol/vectors/lib/x509.mjs';
import { sealDeterministic, signDetached, suiteForKey, open as openHpke } from '../../../pact-protocol/vectors/lib/hpke.mjs';
import { canonical } from '../../../pact-protocol/vectors/lib/canonical.mjs';
import { ENDPOINTS, bharat, BORN, DIES } from '../cast.mjs';
import { RawArgs } from '../port.mjs';
import { createHash, createPublicKey } from 'node:crypto';
import { ZONED } from './certificates.mjs';

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
  // The pinned root and the dialed address are what a renewed chain is held to, and "" is a value like
  // any other (CONTRACT §0), never "none given": read as none, the Go port followed a renewed chain from
  // any root at any address (lead 5 of the port-parity audit; T14). The same leaf at the real root and
  // address, above, is the control that must be followed.
  expect('follow_renewed on the same leaf', { follow: true, leaf: leafDer });
  for (const [what, over, why] of [
    ['a pinned_root of ""', { pinned_root: '' }, 'chain rule 2: root is not the one expected'],
    ['a dialed of ""', { dialed: '' }, 'chain rule 5: endpoint differs from the one in question'],
    ['a pinned_root and a dialed of ""', { pinned_root: '', dialed: '' }, 'chain rule 2: root is not the one expected'],
  ]) {
    add(`follow_renewed on the same leaf, with ${what}`, 'follow_renewed', { answer: { code: 'certificate_renewed', data: { chain: [leafDer, rootDer] } }, pinned_root: rootFp, pinned_leaf: leafDer, dialed: ENDPOINT, now, ...over });
    expect(`follow_renewed on the same leaf, with ${what}`, { follow: false, why });
  }
  // A renewed chain whose leaf names an IPv6 literal with a zone id fails rule 5 for the normal form,
  // before the endpoint is compared with the one dialed (T1, C1, R09).
  for (const endpoint of ZONED.slice(0, 2)) {
    const zonedLeaf = f.alinaLeaf({ endpoint, label: `parity/zone/${endpoint}` });
    add(`follow_renewed to a leaf naming ${endpoint}`, 'follow_renewed', { answer: { code: 'certificate_renewed', data: { chain: [zonedLeaf, rootDer] } }, pinned_root: rootFp, pinned_leaf: leafDer, dialed: ENDPOINT, now });
    expect(`follow_renewed to a leaf naming ${endpoint}`, { follow: false, why: 'chain rule 5: endpoint is not an https URL in normal form' });
  }

  // A request the seed can make and both ports must answer identically: the header carries the rules.
  add('seal_request', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: { name: 'send_message' }, msg_id: 'p-2', ts: at(now), ephemeral_seed: eph(7) });
  add('seal_request with no msg_id at all', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: {}, ts: 1, ephemeral_seed: eph(7) });
  add('seal_request with an ephemeral_seed, which neither port takes', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, form: 'chain', sender_chain: [leafDer, rootDer], method: 'tools/call', params: {}, msg_id: 'x', ts: 1, ephemeral_seed: b64url(new Uint8Array(32)) });
  add('seal_result', 'seal_result', { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, result: { ok: true }, msg_id: 'p-1', ts: at(now), ephemeral_seed: eph(7) });
  add('seal_result with no recipient', 'seal_result', { sender_pkcs8: hostPkcs8, result: {}, msg_id: 'x', ts: 1, ephemeral_seed: eph(7) });
  add('seal_result with neither a result nor an error', 'seal_result', { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, msg_id: 'x', ts: 1, ephemeral_seed: eph(7) });

  // ── a zero value is a value (cluster B of the port-parity audit) ────────────────────────────────
  // Absent takes the contract's default (`params` {}, `method` tools/call, `cty` a call, `exp` ts+600);
  // present, a member is sealed as given, 0 and "" included — as the core and the seed seal it. The Go
  // port read `ts: 0` as absent, `exp: 0` as ts+600, `method: ""` and `cty: ""` as their defaults,
  // and refused an absent `params` as not JSON (T7, F8, R17, R18, C2, F9). Each is held to the
  // envelope the seed seals from the same members and the same ephemeral.
  const toMe = { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, sender_chain: [leafDer, rootDer], ephemeral_seed: eph(7) };
  const seeded = (o) => request({ params: {}, ephemeralSeed: Buffer.alloc(32, 7), ...o });
  for (const [what, args, seedArgs] of [
    ['no params', { msg_id: 'p-3', ts: at(now) }, { msgId: 'p-3' }],
    ['exp 0', { params: {}, msg_id: 'p-4', ts: at(now), exp: 0 }, { msgId: 'p-4', exp: 0 }],
    ['ts 0', { params: {}, msg_id: 'p-5', ts: 0 }, { msgId: 'p-5', ts: 0 }],
    ['an empty method and an empty cty', { params: {}, method: '', cty: '', msg_id: 'p-6', ts: at(now) }, { msgId: 'p-6', method: '', cty: '' }],
  ]) {
    add(`seal_request with ${what}`, 'seal_request', { ...toMe, ...args });
    expect(`seal_request with ${what}`, seeded(seedArgs));
  }
  // -0 is not an integer to the core's reader (serde takes it for a float), and the Go port sealed it
  // as 0. Raw text: JSON.stringify writes -0 as 0.
  for (const m of ['ts', 'exp']) {
    const args = { ...toMe, params: {}, msg_id: 'p-8', ts: 1757000001, exp: 1757000601 };
    add(`seal_request with ${m} -0`, 'seal_request', RawArgs.edit(args, `"${m}":${args[m]}`, `"${m}":-0`));
    expect(`seal_request with ${m} -0`, { error: 'bad_request', why: `${m} is required` });
  }
  // A header's integers are ones it carries as themselves: RFC 8785 writes a number as the double it
  // is, so a ts past 2^53 - 1 was sealed as the nearest double by the core and as itself by the Go
  // port, whose Canonical wrote an int64's digits — two headers for one call, and the core's not the
  // one asked for (a lead of the port-parity verification, 2026-09-30). Both refuse it now, in the
  // core, below the typed API, `ts` first; `exp` absent is ts + 600, which is held too. Raw text where
  // JavaScript cannot write the number.
  {
    const MAX = Number.MAX_SAFE_INTEGER;
    const base = { ...toMe, params: {}, msg_id: 'p-11', ts: 1757000001, exp: 1757000601 };
    const out = (m) => ({ error: 'bad_request', why: `${m} is an integer from -(2^53 - 1) to 2^53 - 1` });
    for (const [what, args, want] of [
      ['a ts of 2^53 + 1', RawArgs.edit(base, '"ts":1757000001', '"ts":9007199254740993'), out('ts')],
      ['a ts of 2^53', { ...base, ts: MAX + 1 }, out('ts')],
      ['a ts of -2^53', { ...base, ts: -(MAX + 1) }, out('ts')],
      ['a ts of the largest i64, and no exp', RawArgs.edit({ ...base, exp: undefined }, '"ts":1757000001', '"ts":9223372036854775807'), out('ts')],
      ['an exp of 2^53 + 1', RawArgs.edit(base, '"exp":1757000601', '"exp":9007199254740993'), out('exp')],
      ['a ts of 2^53 - 1 and no exp, whose default is past it', { ...base, ts: MAX, exp: undefined }, out('exp')],
      // Two faults: the chain is judged after the header's times, and the seed's length before them.
      ['a ts of 2^53 and a chain of one', { ...base, ts: MAX + 1, sender_chain: [leafDer] }, out('ts')],
      ['a ts of 2^53 and no sender_chain', { ...base, ts: MAX + 1, sender_chain: undefined }, out('ts')],
      ['a ts of 2^53 and a seed of 31 bytes', { ...base, ts: MAX + 1, ephemeral_seed: b64url(new Uint8Array(31)) }, { error: 'bad_request', why: 'ephemeral_seed is 32 bytes' }],
    ]) {
      add(`seal_request with ${what}`, 'seal_request', args);
      expect(`seal_request with ${what}`, want);
    }
    // The controls, at the edge: sealed, and held to the envelope the seed seals from the same members.
    for (const [what, ts, exp] of [['a ts and an exp of 2^53 - 1', MAX, MAX], ['a ts of -(2^53 - 1)', -MAX, -MAX + 600]]) {
      add(`seal_request with ${what}`, 'seal_request', { ...base, ts, exp });
      expect(`seal_request with ${what}`, seeded({ msgId: 'p-11', ts, exp }));
    }
    const result = { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, sender_chain: [leafDer, rootDer], result: { ok: true }, msg_id: 'p-12', ts: 1757000001, ephemeral_seed: eph(7) };
    add('seal_result with a ts of 2^53 + 1', 'seal_result', RawArgs.edit(result, '"ts":1757000001', '"ts":9007199254740993'));
    expect('seal_result with a ts of 2^53 + 1', out('ts'));
    add('seal_result with an exp of -2^53', 'seal_result', { ...result, exp: -(MAX + 1) });
    expect('seal_result with an exp of -2^53', out('exp'));
    add('seal_result with a ts of 2^53 - 1 and no exp', 'seal_result', { ...result, ts: MAX });
    expect('seal_result with a ts of 2^53 - 1 and no exp', out('exp'));
  }
  // A JSON value the caller hands in is sealed as the value it is (canonical::in_order, Go inOrder):
  // strings and every number but an i64 or a u64 as RFC 8785 writes them (those keep their digits:
  // below), members in the order written, a member written twice
  // once, where it first appeared, with its last value. The core sealed what serde_json wrote (`1e2`
  // as `100.0`, `-0` as `-0.0`) and the Go port the caller's text as written, duplicates and escapes
  // and all: two plaintexts for one call (a lead of the port-parity verification, 2026-09-30). A
  // request is held to the envelope the seed seals from JSON.parse of the same text — JSON.stringify
  // writes what the ports now write — except where JSON.parse would move a member: it enumerates
  // integer-like names first, so that text is held to the two ports agreeing. Raw text throughout.
  {
    const base = { ...toMe, msg_id: 'p-13', ts: 1757000001, params: '@@' };
    const answer = { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, sender_chain: [leafDer, rootDer], msg_id: 'p-14', ts: 1757000001, ephemeral_seed: eph(7) };
    for (const [what, text, seedReads] of [
      ['a member written twice', '{"a":1,"a":2}', true],
      ['a member written twice around another', '{"b":1,"a":2,"b":3}', true],
      ['an integer past a double', '{"n":123456789012345678901234567890}', true],
      ['escapes JSON.stringify does not write', '{"s":"\\u00e9\\/\\u0041"}', true],
      ['numbers written as JSON.stringify does not write them', '{"x":1.50,"y":1e2,"z":-0,"w":1.0,"v":-0.0,"u":1E-7}', true],
      ['members named by integers, out of order', '{"1":1,"b":2,"0":3}', false],
      ['a list holding each of them', '[{"a":1,"a":[2.50]},"\\/",-0]', true],
    ]) {
      add(`seal_request whose params hold ${what}`, 'seal_request', RawArgs.edit(base, '"params":"@@"', `"params":${text}`));
      if (seedReads) expect(`seal_request whose params hold ${what}`, seeded({ msgId: 'p-13', ts: 1757000001, params: JSON.parse(text) }));
      add(`seal_result whose result holds ${what}`, 'seal_result', RawArgs.edit({ ...answer, result: '@@' }, '"result":"@@"', `"result":${text}`));
      add(`seal_result whose error holds ${what}`, 'seal_result', RawArgs.edit({ ...answer, error: '@@' }, '"error":"@@"', `"error":${text}`));
    }
  }
  // An integer the core holds as one — an i64, or a u64 past it — is sealed by its digits, as the
  // core sealed it before the writer above and as the caller wrote it: RFC 8785's double is the
  // header's rule, and a value the caller hands in keeps every digit it had (the owner's choice (a) on
  // M2 of the review of 2026-09-30). The writer above had printed 12345678901234567891 as
  // 12345678901234567000 in both ports. JavaScript cannot hold these, so the seed cannot seal them: each
  // envelope is opened here, with the seed's HPKE, and its plaintext's bytes are the answer's judge.
  // An integer past 64 bits is no integer to the core; it stays a double, above ('an integer past a
  // double'), and so do -0 and a fraction.
  {
    const base = { ...toMe, msg_id: 'p-15', ts: 1757000001, params: '@@' };
    const answer = { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, sender_chain: [leafDer, rootDer], msg_id: 'p-16', ts: 1757000001, ephemeral_seed: eph(7) };
    const plaintextOf = (got) => {
      const e = got?.envelope ?? got;
      if (typeof e?.protected !== 'string') return null;
      const aad = Buffer.from(e.protected, 'base64url'), { suite } = JSON.parse(aad);
      try { return openHpke(suite, hostKey.priv, hostKey.pub, Buffer.from('PACT-SEAL-v2'), aad, Buffer.from(e.enc, 'base64url'), Buffer.from(e.ct, 'base64url')).toString(); } catch { return null; }
    };
    const holding = (text) => Object.assign((got) => plaintextOf(got)?.includes(text) ?? false, { label: `a plaintext holding ${text}` });
    for (const [what, text, sealed] of [
      ['a u64 past the largest i64', '{"id":12345678901234567891}', '{"id":12345678901234567891}'],
      ['the largest u64', '{"id":18446744073709551615}', '{"id":18446744073709551615}'],
      ['an i64 past 2^53', '{"id":9007199254740993}', '{"id":9007199254740993}'],
      ['the smallest i64', '{"id":-9223372036854775808}', '{"id":-9223372036854775808}'],
      ['an integer past 64 bits, which is a double', '{"id":18446744073709551616}', '{"id":18446744073709552000}'],
      ['a fraction past 2^53, which is a double', '{"id":9007199254740993.0}', '{"id":9007199254740992}'],
    ]) {
      add(`seal_request whose params hold ${what}`, 'seal_request', RawArgs.edit(base, '"params":"@@"', `"params":${text}`));
      expect(`seal_request whose params hold ${what}`, holding(sealed));
      add(`seal_result whose result holds ${what}`, 'seal_result', RawArgs.edit({ ...answer, result: '@@' }, '"result":"@@"', `"result":${text}`));
      expect(`seal_result whose result holds ${what}`, holding(sealed));
    }
  }
  // The JSON literal null is absent (CONTRACT §0), for the members sealed into the body too: both ports
  // sealed `params: null`, `result: null` and `error: null` as present, so a null params was not the
  // contract's `{}`, a null result alone was sealed, and a null result beside an error was refused as
  // both. `params: null` is held to the envelope the seed seals with `{}`.
  add('seal_request with params null', 'seal_request', { ...toMe, params: null, msg_id: 'p-9', ts: at(now) });
  expect('seal_request with params null', seeded({ msgId: 'p-9' }));
  const toThem = { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, sender_chain: [leafDer, rootDer], msg_id: 'p-10', ts: 1, ephemeral_seed: eph(7) };
  add('seal_result with a result that is null', 'seal_result', { ...toThem, result: null });
  expect('seal_result with a result that is null', { error: 'bad_request', why: 'a result carries exactly one of result and error' });
  add('seal_result with a null result beside an error', 'seal_result', { ...toThem, result: null, error: { code: -32000, message: 'no' } });
  add('seal_result with a null error beside a result', 'seal_result', { ...toThem, result: { ok: true }, error: null });
  // The seed seals no results, so these two are held to each other.
  add('seal_result with ts 0 and exp 0', 'seal_result', { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, sender_chain: [leafDer, rootDer], result: { ok: true }, msg_id: 'p-7', ts: 0, exp: 0, ephemeral_seed: eph(7) });
  // Two members missing: the one named is the first the core needs (F10, R19). The chain is judged
  // when the proof member is made, after msg_id and ts; and before the result, whose absence the case
  // above this block's could not reach, since it left the chain out too.
  add('seal_request with neither msg_id nor sender_chain', 'seal_request', { recipient_leaf: leafDer, sender_pkcs8: hostPkcs8, ts: 1, ephemeral_seed: eph(7) });
  expect('seal_request with neither msg_id nor sender_chain', { error: 'bad_request', why: 'msg_id is required' });
  add('seal_result with a chain of one and neither a result nor an error', 'seal_result', { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, sender_chain: [leafDer], msg_id: 'x', ts: 1, ephemeral_seed: eph(7) });
  expect('seal_result with a chain of one and neither a result nor an error', { error: 'bad_request', why: 'sender_chain must be the leaf and the root' });
  add('seal_result with a chain and neither a result nor an error', 'seal_result', { recipient_spki: hostSpki, sender_pkcs8: hostPkcs8, sender_chain: [leafDer, rootDer], msg_id: 'x', ts: 1, ephemeral_seed: eph(7) });
  expect('seal_result with a chain and neither a result nor an error', { error: 'bad_request', why: 'a result carries exactly one of result and error' });

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

  // C13 — the two 30-day windows at their edges, read from contract/contract.json's `Windows`, which a
  // test in each port holds its constant to. The cases above sat about 5.5 and 257.5 days back, so
  // either port's window could have drifted anywhere between and nothing would have said so. A window
  // holds an age strictly under it: one second inside, and exactly at it.
  const { tombstone_s: TOMBSTONE, claim_window_s: CLAIM } = f.defs.Windows.const;
  const tombstoned = (back) => ({ now, envelope: sealed, node: { ...node, tombstones: [{ root: rootFp, at: f.before(back), leaf: olderLeaf }] } });
  add('decide on a peer who returns a second inside the tombstone window', 'decide', tombstoned(TOMBSTONE - 1));
  expect('decide on a peer who returns a second inside the tombstone window', { code: 'ok', forced: 'tombstone' });
  add('decide on a peer who returns exactly at the end of the tombstone window', 'decide', tombstoned(TOMBSTONE));
  expect('decide on a peer who returns exactly at the end of the tombstone window', { code: 'envelope_invalid', why: 'guest may only redeem or request' });
  // A stranger asking to be a contact from an endpoint another root was pinned at: the claim is named
  // while the window holds, and not after.
  const OTHER_ROOT = 'sha256:' + 'B'.repeat(43);
  const asking = request({ params: { name: 'request_contact', arguments: { card: f.card } }, msgId: 'p-claim' });
  const claimed = (back) => ({ now, envelope: asking, node: { ...node, endpoint: 'https://bharat.example/mcp', former_endpoints: [{ root: OTHER_ROOT, endpoint: ENDPOINT, at: f.before(back) }] } });
  add('decide on a stranger at an endpoint another root left a second inside the claim window', 'decide', claimed(CLAIM - 1));
  expect('decide on a stranger at an endpoint another root left a second inside the claim window', { code: 'ok', address_claim: OTHER_ROOT });
  add('decide on a stranger at an endpoint another root left exactly at the end of the claim window', 'decide', claimed(CLAIM));
  expect('decide on a stranger at an endpoint another root left exactly at the end of the claim window', { code: 'ok', address_claim: null });

  // A root the host holds — a pin's, a tombstone's, a former endpoint's — is a Fingerprint, and one
  // that is not is the host's damaged state: an error of the call, named by its path, as a member of
  // the wrong type is. Both ports read it as a root nothing matches, so a pin or a former endpoint
  // whose root was 'abc' came back as the answer's `address_claim: "abc"`, which the contract types as
  // a Fingerprint, and a tombstone whose root was 'abc' was skipped whatever else in it did not read
  // (a lead of the port-parity verification, 2026-09-30, followed from refresh_check's pin).
  {
    const notFp = (path) => ({ error: 'bad_request', why: `${path}.root is not a fingerprint` });
    const heldLeaf = open(leafForm, { pins: [{ ...pinned[0], root: 'abc' }] });
    for (const [what, fn, args, want] of [
      ['decide on a stranger at an endpoint a former endpoint whose root is not a fingerprint left', 'decide', { ...claimed(CLAIM - 1), node: { ...claimed(CLAIM - 1).node, former_endpoints: [{ ...claimed(CLAIM - 1).node.former_endpoints[0], root: 'abc' }] } }, notFp('node.former_endpoints[0]')],
      ['decide on a peer with a tombstone whose root is not a fingerprint', 'decide', { ...tombstoned(60), node: { ...tombstoned(60).node, tombstones: [{ ...tombstoned(60).node.tombstones[0], root: 'abc' }] } }, notFp('node.tombstones[0]')],
      ['decide on an envelope from a contact whose pin\'s root is not a fingerprint', 'decide', { now, envelope: sealed, node: { ...node, pins: [{ ...pinned[0], root: 'abc' }] } }, notFp('node.pins[0]')],
      ['decide with a second pin whose root is empty', 'decide', { now, envelope: sealed, node: { ...node, pins: [pinned[0], { ...pinned[0], root: '' }] } }, notFp('node.pins[1]')],
      ['open_result in the leaf form, from a held leaf whose pin\'s root is not a fingerprint', 'open_result', heldLeaf, notFp('pins[0]')],
    ]) {
      add(what, fn, args);
      expect(what, want);
    }
  }
  // CW-11 — why a caller proven by a chain is a guest, and whether a pin stands behind it. The node
  // demoted a caller by matching the words of `why` ('blocked', 'superseded leaf') and the cloud
  // re-derived the same fact from its rows; the core answers it as a member, `demote`, and `why` is
  // one of the three words contract/contract.json's GuestWhy fixes. No case reached `blocked` or
  // `superseded leaf` before these, so a rewording of either would have gone unseen.
  const elsewhere = { ...node, endpoint: 'https://bharat.example/mcp' };
  const pinnedNewer = b64url(buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: ENDPOINT, notBefore: new Date('2026-09-10T00:00:00Z'), notAfter: new Date('2027-09-10T00:00:00Z'), label: 'parity/cw11/newer' }));
  for (const [why, pins, demote] of [
    ['unknown root', [], false],
    ['blocked', [{ ...pinned[0], state: 'blocked' }], true],
    ['superseded leaf', [{ ...pinned[0], leaf: pinnedNewer }], true],
  ]) {
    add(`decide on a caller proven by a chain who is a guest: ${why}`, 'decide', { now, envelope: asking, node: { ...elsewhere, pins } });
    expect(`decide on a caller proven by a chain who is a guest: ${why}`, { code: 'ok', tier: 'guest', why, demote, address_claim: null });
  }

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
    // It waits, and names what the signature proved, so a host can seal the refusal back (the
    // port-parity lead 2): the root, the address, the leaf the signature verified under, the form, and
    // the request's msg_id. `seen` is not an effect: the call was not taken.
    expect(control, { code: 'pending_approval', root: rootFp, endpoint, leaf: form === 'chain' ? b64url(chainLeaf) : leafDer, form, msg_id: 'p-21' });
  }

  // TC-3 — §13.1#1: `enc` is exactly the suite's Npk (65 bytes for PACT-SEAL-P256, 32 for
  // PACT-SEAL-X25519). `sig` covers protected ‖ enc ‖ ct with nothing between them, so a byte moved
  // across the enc/ct boundary leaves the signed bytes as they were: the forgery is signed, and the
  // one thing that refuses it is the length. One byte short and one byte long, under each suite, on
  // both doors a peer's envelope reaches: `decide` (a request) and `open_result` (a result). Only the
  // P-256 request had a holder, the seed's intrusion scenario through `decide`.
  const LENGTH = { code: 'envelope_invalid', why: "encapsulated key is not the suite's length" };
  const moved = (e, by) => {
    const enc = Buffer.from(e.enc, 'base64url'), ct = Buffer.from(e.ct, 'base64url');
    return by < 0
      ? { ...e, enc: b64url(enc.subarray(0, enc.length - 1)), ct: b64url(Buffer.concat([enc.subarray(enc.length - 1), ct])) }
      : { ...e, enc: b64url(Buffer.concat([enc, ct.subarray(0, 1)])), ct: b64url(ct.subarray(1)) };
  };
  // Bharat's host holds a P-256 leaf, so what is sealed to it is sealed under PACT-SEAL-P256.
  const bharatLeaf = buildLeaf({ cn: bharat.cn, rootCn: bharat.cn, root: bharat.root, hostKey: bharat.host, endpoint: ENDPOINTS.bharat, notBefore: BORN, notAfter: DIES, label: 'parity/bharat-leaf' });
  const bharatNode = {
    ...node, endpoint: ENDPOINTS.bharat, chain: [b64url(bharatLeaf), f.p256RootDer],
    keys: [{ kid: fingerprint(bharat.host.pub), leaf: b64url(bharatLeaf), pkcs8: b64url(pkcs8Of(bharat.host.priv)), current: true }],
  };
  const bharatSpki = b64url(spkiOf(bharat.host.pub)), bharatPkcs8 = b64url(pkcs8Of(bharat.host.priv));
  for (const [suite, recipient, toResult] of [
    ['PACT-SEAL-X25519', { envelope: sealed, node }, { envelope: chainForm, args: {} }],
    ['PACT-SEAL-P256', { envelope: request({ params: { name: 'send_message' }, msgId: 'p-npk', recipientLeaf: bharatLeaf }), node: bharatNode },
      { envelope: answerTo({ recipient_spki: bharatSpki }), args: { my_pkcs8: bharatPkcs8, my_spki: bharatSpki } }],
  ]) {
    for (const [by, what] of [[-1, 'one byte short'], [1, 'one byte long']]) {
      const onDecide = `decide on a ${suite} envelope whose encapsulated key is ${what}`;
      add(onDecide, 'decide', { now, envelope: moved(recipient.envelope, by), node: recipient.node });
      expect(onDecide, LENGTH);
      const onOpen = `open_result on a ${suite} answer whose encapsulated key is ${what}`;
      add(onOpen, 'open_result', open(moved(toResult.envelope, by), toResult.args));
      expect(onOpen, { error: LENGTH.code, why: LENGTH.why });
    }
  }


  // ── the objects inside a member (T9, F11, F12, F13, R20, R22, T8, S1-1) ─────────────────────────
  // Each was read through a zero value in one port and refused in the other's words (serde's, or
  // "decide input does not read" / "envelope members" for every fault). Both ports now read them by
  // hand, in the contract's order, and name the member by its path. To `decide` they are the host's
  // arguments (`bad_request`); to `open_result` the envelope is the peer's answer (`envelope_invalid`,
  // its note), and only an absent one is the caller's omission (§0).
  const { sig: _sig, ...noSig } = sealed;
  const { endpoint: _endpoint, ...noEndpoint } = node;
  for (const [what, args, want] of [
    ['an envelope with no sig', { now, envelope: noSig, node }, 'envelope.sig is required'],
    ['an envelope that is not an object', { now, envelope: 'x', node }, 'envelope is required'],
    ['a node with no endpoint', { now, envelope: sealed, node: noEndpoint }, 'node.endpoint is required'],
    ['a node that is not an object', { now, envelope: sealed, node: 5 }, 'node is required'],
    ['a held key with no kid', { now, envelope: sealed, node: { ...node, keys: [{ leaf: leafDer, pkcs8: hostPkcs8 }] } }, 'node.keys[0].kid is required'],
    ['a pin with no leaf', { now, envelope: sealed, node: { ...node, pins: [{ root: rootFp, endpoint: ENDPOINT }] } }, 'node.pins[0].leaf is required'],
    ['pins that are not a list', { now, envelope: sealed, node: { ...node, pins: 'x' } }, 'node.pins is required'],
    ['a seen entry that is not a string', { now, envelope: sealed, node: { ...node, seen: ['m', 5] } }, 'node.seen[1] is required'],
    ['an accept_new_hosts that is neither auto nor ask', { now, envelope: sealed, node: { ...node, accept_new_hosts: '' } }, 'node.accept_new_hosts is auto or ask'],
    ['a node and an envelope both short a member', { now, envelope: noSig, node: noEndpoint }, 'node.endpoint is required'],
  ]) {
    add(`decide with ${what}`, 'decide', args);
    expect(`decide with ${what}`, { error: 'bad_request', why: want });
  }
  // `accept_new_hosts` absent is `auto` (SPEC §5.3, the contract's NodeState): a pinned contact's chain
  // at another endpoint re-pins it, where the Go port read the zero value as `ask` and held it (T8).
  const { accept_new_hosts: _policy, ...unsaid } = node;
  const movedCall = request({ senderChain: [movedLeaf, f.rootDerBytes], params: { name: 'send_message' }, msgId: 'p-t8' });
  add('decide on a contact at a new endpoint, the node saying no accept_new_hosts', 'decide', { now, envelope: movedCall, node: { ...unsaid, pins: pinned } });
  expect('decide on a contact at a new endpoint, the node saying no accept_new_hosts', { code: 'ok', tier: 'contact', endpoint: MOVED });
  const { ct: _ct, ...noCt } = chainForm;
  for (const [what, args, want] of [
    ['an envelope with no ct', open(noCt), { error: 'envelope_invalid', why: 'envelope.ct is required' }],
    ['an envelope that is not an object', open('x'), { error: 'envelope_invalid', why: 'envelope is required' }],
    ['a pin with no root', open(leafForm, { pins: [{ endpoint: ENDPOINT, leaf: leafDer }] }), { error: 'bad_request', why: 'pins[0].root is required' }],
    ['a pin whose root is not a string', open(leafForm, { pins: [{ root: 5, endpoint: ENDPOINT, leaf: leafDer }] }), { error: 'bad_request', why: 'pins[0].root is required' }],
    ['a pin that is not an object', open(leafForm, { pins: ['x'] }), { error: 'bad_request', why: 'pins[0] is required' }],
  ]) {
    add(`open_result with ${what}`, 'open_result', args);
    expect(`open_result with ${what}`, want);
  }
  // `pins: null` is no pins (§0): the core refused it in serde's words. The expectation is read from
  // the answer's `result` (js/parity.mjs), the peer's `{ok: 1}`: the answer opened.
  add('open_result with pins that are null', 'open_result', open(chainForm, { pins: null }));
  expect('open_result with pins that are null', { ok: 1 });
  // The peer's answer as it was sent: a code or data of the wrong type is an answer, not a caller's
  // mistake (the contract's `answer: true`), as the core gives it (F14, R22).
  add('follow_renewed on an answer whose code is not a string', 'follow_renewed', follow({ code: 5 }));
  expect('follow_renewed on an answer whose code is not a string', { follow: false, why: 'not certificate_renewed' });
  add('follow_renewed on an answer whose data is not an object', 'follow_renewed', follow({ code: 'certificate_renewed', data: 5 }));
  expect('follow_renewed on an answer whose data is not an object', { follow: false, why: 'no chain' });
  add('follow_renewed on an answer that is not an object', 'follow_renewed', follow('x'));
  expect('follow_renewed on an answer that is not an object', { follow: false, why: 'not certificate_renewed' });

  // ── an empty string is a value (cluster D) ────────────────────────────────────────────────────
  add('open_result in the chain form with an expected_root that is empty', 'open_result', open(chainForm, { expected_root: '' }));
  expect('open_result in the chain form with an expected_root that is empty', { error: 'envelope_invalid', why: 'chain rule 2: root is not the one expected' });
  // follow_renewed's pinned root and dialed address are required, and "" is held like any value: the
  // Go port's typed FollowRenewed read it as "not given" and followed a renewed chain from any root
  // at any address (T14's corrected text).
  add('follow_renewed with a pinned_root that is empty', 'follow_renewed', { ...follow({ code: 'certificate_renewed', data: { chain: [leafDer, rootDer] } }), pinned_root: '' });
  expect('follow_renewed with a pinned_root that is empty', { follow: false, why: 'chain rule 2: root is not the one expected' });
  add('follow_renewed with a dialed address that is empty', 'follow_renewed', { ...follow({ code: 'certificate_renewed', data: { chain: [leafDer, rootDer] } }), dialed: '' });
  expect('follow_renewed with a dialed address that is empty', { follow: false, why: 'chain rule 5: endpoint differs from the one in question' });

  // ── what one port's parser refuses and the other's reads, inside an envelope (R40, S3-2) ──────
  // A body or a header as TEXT, sealed and signed with the seed's own HPKE and signature: neither the
  // seed's sealEnvelope nor `seal_result` can carry a number infinite as a double (JSON.stringify
  // writes it as null, and both ports refuse it at their boundary). Everything else about each
  // envelope is good, so a refusal is the text's. The core refused each — serde_json does not read
  // them — and the Go port decided `ok` on a request whose body held 1e400, opened such a result, and
  // named a header holding one `header member types`; one envelope was accepted by a node and refused
  // by a hosted identity. The controls hold the largest double, and 127 deep.
  const { leafDerBytes, rootDerBytes, callerKey } = f;
  const sealText = ({ to, cty, msgId, body, header = (t) => t }) => {
    const suite = suiteForKey(to);
    const aad = Buffer.from(header(canonical({ v: 2, suite, kid: fingerprint(to), msg_id: msgId, ts: at(now), exp: at(now) + 600, cty })));
    const { enc, ct } = sealDeterministic(suite, to, Buffer.from('PACT-SEAL-v2'), aad, Buffer.from(body), Buffer.alloc(32, 9));
    return { protected: b64url(aad), enc: b64url(enc), ct: b64url(ct), sig: b64url(signDetached(hostKey.priv, Buffer.concat([aad, enc, ct]))) };
  };
  const toMyself = parse(leafDerBytes).publicKey;
  const chainText = JSON.stringify([b64url(leafDerBytes), b64url(rootDerBytes)]);
  const nestedText = (n) => '['.repeat(n) + '1' + ']'.repeat(n);
  const callText = (msgId, argsText, o = {}) =>
    sealText({ to: toMyself, cty: 'application/pact-call+json', msgId, body: `{"method":"tools/call","params":{"name":"send_message","arguments":${argsText}},"chain":${chainText}}`, ...o });
  const pinnedNode = { ...node, pins: pinned };
  const notJSON = { code: 'envelope_invalid', why: 'does not open' };
  // The body is the first container and params the second; `arguments` is the arrays.
  for (const [what, msgId, argsText, want] of [
    ['a body holding a number past the largest double', 'p-r40-1', '{"n":1e400}', notJSON],
    ['a body nested 128 deep', 'p-r40-2', nestedText(126), notJSON],
    ['a body holding the largest double', 'p-r40-3', '{"n":1.7976931348623157e308}', { code: 'ok', tier: 'contact' }],
    ['a body nested 127 deep', 'p-r40-4', nestedText(125), { code: 'ok', tier: 'contact' }],
  ]) {
    add(`decide on an envelope with ${what}`, 'decide', { now, envelope: callText(msgId, argsText), node: pinnedNode });
    expect(`decide on an envelope with ${what}`, want);
  }
  add('decide on an envelope whose header holds a ts past the largest double', 'decide', {
    now, envelope: callText('p-r40-5', '{}', { header: (t) => t.replace(`"ts":${at(now)}`, '"ts":1e400') }), node: pinnedNode,
  });
  expect('decide on an envelope whose header holds a ts past the largest double', { code: 'envelope_invalid', why: 'protected is not JSON' });
  // S3-1, in the header: `v`, `ts` and `exp` are integers as the core reads one (serde_json's
  // `as_i64`), so a `ts` or `exp` written `-0`, or written with a fraction, is `header member types`.
  // The Go port read -0 as 0 and went on to the time window, where the core refused the header's
  // types; one envelope was two answers. The fraction both ports refused already; the seed decides it
  // `ok` and reads -0 as 0, which pact-protocol PR #10 changes.
  const headerHolding = (member, text) => (t) => t.replace(member === 'ts' ? `"ts":${at(now)}` : `"exp":${at(now) + 600}`, `"${member}":${text}`);
  const typesRefused = { code: 'envelope_invalid', why: 'header member types' };
  // With them, the other spellings the seed now judges on their text (pact-protocol PR #10): an exponent
  // and a number past 64 bits are no integer; past 2^53 and within 64 bits is one, judged by its time.
  add('decide on an envelope whose header holds a ts past 2^53 and within 64 bits', 'decide', { now, envelope: callText('p-s3-1-big', '{}', { header: headerHolding('ts', '9223372036854775807') }), node: pinnedNode });
  expect('decide on an envelope whose header holds a ts past 2^53 and within 64 bits', { code: 'envelope_invalid', why: 'outside the time window' });
  for (const [what, member, text] of [
    ['a ts of -0', 'ts', '-0'], ['an exp of -0', 'exp', '-0'], ['a ts written with a fraction', 'ts', `${at(now)}.0`],
    ['a ts written with an exponent', 'ts', `${at(now) / 1e8}e8`], ['a ts past 64 bits', 'ts', '9223372036854775808'],
  ]) {
    add(`decide on an envelope whose header holds ${what}`, 'decide', { now, envelope: callText(`p-s3-1-${member}`, '{}', { header: headerHolding(member, text) }), node: pinnedNode });
    expect(`decide on an envelope whose header holds ${what}`, typesRefused);
    const answer = sealText({ to: callerKey.pub, cty: 'application/pact-result+json', msgId: 'r-1', body: `{"result":{},"chain":${chainText}}`, header: headerHolding(member, text) });
    add(`open_result on an answer whose header holds ${what}`, 'open_result', open(answer));
    expect(`open_result on an answer whose header holds ${what}`, { error: 'envelope_invalid', why: 'header member types' });
  }
  const resultText = (resultJSON) =>
    sealText({ to: callerKey.pub, cty: 'application/pact-result+json', msgId: 'r-1', body: `{"result":${resultJSON},"chain":${chainText}}` });
  add('open_result on an answer whose result holds a number past the largest double', 'open_result', open(resultText('{"n":1e400}')));
  expect('open_result on an answer whose result holds a number past the largest double', { error: 'envelope_invalid', why: 'does not open' });
  add('open_result on an answer whose result holds the largest double', 'open_result', open(resultText('{"n":1.7976931348623157e308}')));
  // An answer is held by its `result`, which is what the peer sent.
  expect('open_result on an answer whose result holds the largest double', { n: 1.7976931348623157e308 });

  // ── M1 of the review of 2026-09-30: text that is not UTF-8, and half a surrogate pair ─────────────
  // serde_json, which the core reads with, refuses bytes that are not UTF-8 and a \u escape of half a
  // surrogate pair; encoding/json reads the first as U+FFFD and the second as U+FFFD too. So a call
  // whose header msg_id was "\ud800", or whose body held one or a raw 0xFF, was `protected is not JSON`
  // or `does not open` to the core (the cloud) and `ok` to the Go port (the node), and so was the
  // seed's node until pact-protocol#10 (2ba05a1). A surrogate pair, and an escaped backslash before a
  // `u`, are the controls. `@` in a text stands for the bytes given.
  const bytesAt = (text, ...b) => { const t = Buffer.from(text), i = t.indexOf('@'); return Buffer.concat([t.subarray(0, i), Buffer.from(b), t.subarray(i + 1)]); };
  const msgIdText = (text) => (t) => t.replace(/"msg_id":"[^"]*"/, `"msg_id":${text}`);
  const rawBody = (msgId, argsText, ...b) => sealText({ to: toMyself, cty: 'application/pact-call+json', msgId, body: bytesAt(`{"method":"tools/call","params":{"name":"send_message","arguments":${argsText}},"chain":${chainText}}`, ...b) });
  const headerNotJSON = { code: 'envelope_invalid', why: 'protected is not JSON' };
  for (const [what, envelope, want] of [
    ['a header whose msg_id is half a surrogate pair', callText('p-m1-1', '{}', { header: msgIdText('"\\ud800"') }), headerNotJSON],
    ['a header holding a byte that is not UTF-8', callText('p-m1-2', '{}', { header: (t) => bytesAt(msgIdText('"@"')(t), 0xff) }), headerNotJSON],
    ['a body whose value is half a surrogate pair', callText('p-m1-3', '{"text":"\\ud800"}'), notJSON],
    ['a body whose value is the low half of a surrogate pair', callText('p-m1-4', '{"text":"\\udc00"}'), notJSON],
    ['a body whose member name is half a surrogate pair', callText('p-m1-5', '{"\\ud800":1}'), notJSON],
    ['a body holding bytes that are not UTF-8', rawBody('p-m1-6', '{"text":"@"}', 0xff, 0xfe), notJSON],
    ['a body holding a surrogate pair', callText('p-m1-7', '{"text":"\\ud83d\\ude00"}'), { code: 'ok', tier: 'contact' }],
    ['a body holding an escaped backslash before a u', callText('p-m1-8', '{"text":"\\\\ud800"}'), { code: 'ok', tier: 'contact' }],
  ]) {
    add(`decide on an envelope with ${what}`, 'decide', { now, envelope, node: pinnedNode });
    expect(`decide on an envelope with ${what}`, want);
  }
  const rawResult = (...b) => sealText({ to: callerKey.pub, cty: 'application/pact-result+json', msgId: 'r-1', body: bytesAt(`{"result":{"text":"@"},"chain":${chainText}}`, ...b) });
  const answerNotJSON = { error: 'envelope_invalid', why: 'does not open' };
  for (const [what, answer, want] of [
    ['an answer whose header msg_id is half a surrogate pair', sealText({ to: callerKey.pub, cty: 'application/pact-result+json', msgId: 'r-1', body: `{"result":{},"chain":${chainText}}`, header: msgIdText('"\\ud800"') }), { error: 'envelope_invalid', why: 'protected is not JSON' }],
    ['an answer whose result holds half a surrogate pair', resultText('{"text":"\\ud800"}'), answerNotJSON],
    ['an answer whose result names a member with half a surrogate pair', resultText('{"\\udc00":1}'), answerNotJSON],
    ['an answer whose result holds bytes that are not UTF-8', rawResult(0xff, 0xfe), answerNotJSON],
    ['an answer whose result holds a surrogate pair', resultText('{"text":"\\ud83d\\ude00"}'), { text: '\u{1F600}' }],
  ]) {
    add(`open_result on ${what}`, 'open_result', open(answer));
    expect(`open_result on ${what}`, want);
  }

  // ── G: the keys an envelope is sealed to (T4, F6, R14) ───────────────────────────────────────────
  //
  // The X25519 suite is for an Ed25519 recipient, converted (CONTRACT §5; SPEC §13.1's suite table),
  // and a leaf cannot hold any other: a bare X25519 key is outside the profile, and refused where it is
  // read, as every key outside it is. The core sealed to one and the Go port refused it as a suite
  // that does not fit; both named an X25519 suite for it.
  const info = 'PACT-SEAL-v2', plaintext = b64url(new Uint8Array([1, 2, 3]));
  for (const [kind, { spki, oid }] of Object.entries(f.foreign)) {
    const refused = { error: 'unsupported', why: `unsupported key type ${oid}` };
    add(`suite_for a key outside the profile: ${kind}`, 'suite_for', { spki: b64url(spki) });
    expect(`suite_for a key outside the profile: ${kind}`, refused);
    for (const suite of ['PACT-SEAL-X25519', 'PACT-SEAL-P256']) {
      add(`hpke_seal under ${suite} to a key outside the profile: ${kind}`, 'hpke_seal', { suite, recipient_spki: b64url(spki), info, plaintext });
      expect(`hpke_seal under ${suite} to a key outside the profile: ${kind}`, refused);
    }
    add(`hpke_open as a key outside the profile: ${kind}`, 'hpke_open', { ...hpkeOpen, recipient_spki: b64url(spki) });
    expect(`hpke_open as a key outside the profile: ${kind}`, refused);
  }
  // A suite that is not the recipient key's is the envelope's refusal, in the envelope layer's words.
  // The core said `unsupported`, which hpke_seal does not declare (F6, R14).
  for (const [suite, spki, what] of [['PACT-SEAL-X25519', p256Spki, 'a P-256 key'], ['PACT-SEAL-P256', hostSpki, 'an Ed25519 key']]) {
    add(`hpke_seal under ${suite} to ${what}`, 'hpke_seal', { suite, recipient_spki: spki, info, plaintext });
    expect(`hpke_seal under ${suite} to ${what}`, { error: 'envelope_invalid', why: 'suite does not fit the key' });
  }
  // An Ed25519 key of small order converts to a low-order X25519 point, and every seal to it meets an
  // all-zero DH output, which SPEC §13.1 refuses. A leaf holding one validates, in both ports, so a
  // seal_request reaches it. The core said `internal`, a code no input is to reach (CONTRACT §0), and
  // the Go port `envelope_invalid` (T4). The identity (y = 1) and y = -1 both map to u = 0.
  const smallOrder = { 'the identity': '0100000000000000000000000000000000000000000000000000000000000000', 'y = -1': 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f' };
  const lowOrder = { error: 'envelope_invalid', why: 'all-zero DH output: low-order point' };
  for (const [what, point] of Object.entries(smallOrder)) {
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(point, 'hex')]);
    const leaf = f.alinaLeaf({ hostKey: { pub: createPublicKey({ key: spki, format: 'der', type: 'spki' }) }, label: `parity/small-order/${what}` });
    add(`hpke_seal to an Ed25519 key of small order: ${what}`, 'hpke_seal', { suite: 'PACT-SEAL-X25519', recipient_spki: b64url(spki), info, plaintext, ephemeral_seed: eph(5) });
    expect(`hpke_seal to an Ed25519 key of small order: ${what}`, lowOrder);
    add(`seal_request to a leaf holding an Ed25519 key of small order: ${what}`, 'seal_request', { recipient_leaf: leaf, sender_pkcs8: hostPkcs8, sender_chain: [leafDer, rootDer], params: {}, msg_id: 'p-low', ts: at(now), ephemeral_seed: eph(7) });
    expect(`seal_request to a leaf holding an Ed25519 key of small order: ${what}`, lowOrder);
    add(`seal_result to an Ed25519 key of small order: ${what}`, 'seal_result', { recipient_spki: b64url(spki), sender_pkcs8: hostPkcs8, sender_chain: [leafDer, rootDer], result: { ok: true }, msg_id: 'p-low', ts: at(now), ephemeral_seed: eph(7) });
    expect(`seal_result to an Ed25519 key of small order: ${what}`, lowOrder);
  }

  // ── T5: an open is by a key of the suite's own algorithm ─────────────────────────────────────────
  //
  // The Go port's open read a P-256 key's seed, which it does not have, under PACT-SEAL-X25519, and so
  // used the scalar of the empty seed — SHA-512 of nothing, clamped: a public constant. Any P-256 key
  // then opened a seal to the Ed25519 key whose X25519 form is that constant's point, through
  // hpke_open and decide alike; the core refuses a P-256 key there. The crafted key is computed here
  // from the empty seed (RFC 7748 §4.1 backwards: y = (u - 1) / (u + 1)), and the seal is the seed's.
  const P = (1n << 255n) - 19n;
  const le = (b) => b.reduceRight((v, x) => (v << 8n) | BigInt(x), 0n);
  const modpow = (b, e) => { let r = 1n; b %= P; for (; e > 0n; e >>= 1n, b = (b * b) % P) if (e & 1n) r = (r * b) % P; return r; };
  const emptyScalar = createHash('sha512').update(Buffer.alloc(0)).digest().subarray(0, 32);
  const u = le(Buffer.from(x25519FromSeed(emptyScalar).pub.export({ format: 'jwk' }).x, 'base64url'));
  const y = (((u - 1n + P) % P) * modpow((u + 1n) % P, P - 2n)) % P;
  const craftedSpki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(Array.from({ length: 32 }, (_, i) => Number((y >> BigInt(8 * i)) & 0xffn)))]);
  const craftedPub = createPublicKey({ key: craftedSpki, format: 'der', type: 'spki' });
  const admitted = sealDeterministic('PACT-SEAL-X25519', craftedPub, Buffer.from('PACT-SEAL-v2'), Buffer.alloc(0), Buffer.from('admitted'), Buffer.alloc(32, 3));
  const doesNotOpen = { error: 'envelope_invalid', why: 'does not open' };
  for (const [who, pkcs8] of [['a P-256 key', f.p256Pkcs8], ['another P-256 key', b64url(pkcs8Of(bharat.host.priv))]]) {
    add(`hpke_open of a seal to the empty seed's key, by ${who}`, 'hpke_open', { suite: 'PACT-SEAL-X25519', recipient_pkcs8: pkcs8, recipient_spki: b64url(craftedSpki), info: 'PACT-SEAL-v2', aad: '', enc: b64url(admitted.enc), ct: b64url(admitted.ct) });
    expect(`hpke_open of a seal to the empty seed's key, by ${who}`, doesNotOpen);
  }
  // The control: a seal opened by the key it was made for.
  expect('hpke_open of what hpke_seal made', { plaintext: b64url(new Uint8Array([1, 2, 3])) });
  // An Ed25519 key under the P-256 suite, and a P-256 key under the X25519 suite, each with the other
  // key's public half: the private key is held to the suite before anything else.
  const toP256 = sealDeterministic('PACT-SEAL-P256', f.p256Key.pub, Buffer.from('PACT-SEAL-v2'), Buffer.alloc(0), Buffer.from('x'), Buffer.alloc(32, 4));
  add('hpke_open under the P-256 suite by an Ed25519 key', 'hpke_open', { suite: 'PACT-SEAL-P256', recipient_pkcs8: hostPkcs8, recipient_spki: p256Spki, info: 'PACT-SEAL-v2', aad: '', enc: b64url(toP256.enc), ct: b64url(toP256.ct) });
  expect('hpke_open under the P-256 suite by an Ed25519 key', doesNotOpen);
  add('hpke_open under the X25519 suite by a P-256 key', 'hpke_open', { ...hpkeOpen, recipient_pkcs8: f.p256Pkcs8 });
  expect('hpke_open under the X25519 suite by a P-256 key', doesNotOpen);
  // And through decide: a node that holds the crafted key's leaf with a P-256 key beside it. The Go
  // port opened the stranger's call and decided on it.
  const craftedLeaf = buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey: { pub: craftedPub }, endpoint: ENDPOINT, notBefore: BORN, notAfter: DIES, label: 'parity/empty-seed' });
  const toCrafted = request({ params: { name: 'send_message' }, msgId: 'p-t5', recipientLeaf: craftedLeaf });
  const craftedNode = { ...node, chain: [b64url(craftedLeaf), rootDer], keys: [{ kid: fingerprint(craftedPub), leaf: b64url(craftedLeaf), pkcs8: f.p256Pkcs8, current: true }] };
  add('decide on a call sealed to the empty seed\'s key, held beside a P-256 key', 'decide', { now, envelope: toCrafted, node: craftedNode });
  expect('decide on a call sealed to the empty seed\'s key, held beside a P-256 key', { code: 'envelope_invalid', why: 'does not open' });

  // A held or pinned leaf carrying a key outside the profile, inside the node state and the pins: the
  // key is refused where it is read, `unsupported`, as at the top level. The Go port read the leaf and
  // made its error `parse` (R12, T2). What a held PKCS #8 key or a chain-form pin that does not read is
  // answered is R23's and T10's (cluster H), not this.
  const heldKey = node.keys[0];
  for (const [kind, { oid }] of Object.entries(f.foreign)) {
    const leaf = f.foreignLeaf(kind), refused = { error: 'unsupported', why: `unsupported key type ${oid}` };
    add(`decide with a held leaf holding a key outside the profile: ${kind}`, 'decide', { now, envelope: sealed, node: { ...node, keys: [{ ...heldKey, leaf }] } });
    expect(`decide with a held leaf holding a key outside the profile: ${kind}`, refused);
    add(`decide with a pinned leaf holding a key outside the profile: ${kind}`, 'decide', { now, envelope: sealed, node: { ...node, pins: [{ ...pinned[0], leaf }] } });
    expect(`decide with a pinned leaf holding a key outside the profile: ${kind}`, refused);
    add(`open_result in the leaf form, with a pin holding a key outside the profile: ${kind}`, 'open_result', open(leafForm, { pins: [{ root: rootFp, endpoint: ENDPOINT, leaf, state: 'active' }] }));
    expect(`open_result in the leaf form, with a pin holding a key outside the profile: ${kind}`, refused);
  }

  // ── H: what a peer put in its plaintext, and what a host holds, is read strictly ─────────────────
  //
  // A chain member in the plaintext that does not read: the Go port and the seed skipped a stray
  // character and the chain validated; the core refused it, as `plaintext shape` in decide and as a
  // `parse` error of the CALL in open_result, whose refusals of an envelope are all envelope_invalid
  // (T10, X9). The plaintext's shape now, in both ports and the seed. Sealed and signed by the seed over
  // the body as written; the controls, padded, read.
  const leafText = b64url(leafDerBytes), rootText = b64url(rootDerBytes);
  const chainCall = (msgId, chain) => sealText({ to: toMyself, cty: 'application/pact-call+json', msgId, body: JSON.stringify({ method: 'tools/call', params: { name: 'send_message', arguments: {} }, chain }) });
  const chainAnswer = (chain) => sealText({ to: callerKey.pub, cty: 'application/pact-result+json', msgId: 'r-1', body: JSON.stringify({ result: { ok: 1 }, chain }) });
  for (const [what, member, reads] of [
    ['a stray character', leafText.slice(0, 8) + '!' + leafText.slice(8), false],
    ['a vertical tab', leafText.slice(0, 8) + '\u000b' + leafText.slice(8), false],
    ['padding (the control)', leafText + '='.repeat((4 - (leafText.length % 4)) % 4), true],
  ]) {
    const onDecide = `decide on a call whose plaintext chain's leaf has ${what}`;
    add(onDecide, 'decide', { now, envelope: chainCall('p-h', [member, rootText]), node: pinnedNode });
    expect(onDecide, reads ? { code: 'ok', tier: 'contact' } : { code: 'envelope_invalid', why: 'plaintext shape' });
    const onOpen = `open_result on an answer whose plaintext chain's leaf has ${what}`;
    add(onOpen, 'open_result', open(chainAnswer([member, rootText])));
    // An answer is held by its `result`, which is what the peer sent.
    expect(onOpen, reads ? { ok: 1 } : { error: 'envelope_invalid', why: 'plaintext shape' });
  }

  // The caller's pin, in the chain form: one whose leaf does not read, or reads to a key outside the
  // profile, is an error of the call in its reader's class, as the core's `?` has it. The Go port read
  // it leniently and answered `superseded leaf` for any that did not parse (T10).
  const pinOf = (leaf) => ({ pins: [{ root: rootFp, endpoint: ENDPOINT, leaf, state: 'active' }] });
  add('open_result in the chain form, with a pin whose leaf is not base64url', 'open_result', open(chainForm, pinOf('!!!')));
  expect('open_result in the chain form, with a pin whose leaf is not base64url', { error: 'parse', why: 'not base64url' });
  add('open_result in the chain form, with a pin whose leaf is not a certificate', 'open_result', open(chainForm, pinOf('AAAA')));
  expect('open_result in the chain form, with a pin whose leaf is not a certificate', { error: 'parse' });
  add('open_result in the chain form, with a pin whose leaf has a stray character', 'open_result', open(chainForm, pinOf(leafDer.slice(0, 8) + '!' + leafDer.slice(8))));
  expect('open_result in the chain form, with a pin whose leaf has a stray character', { error: 'parse', why: 'not base64url' });
  for (const [kind, { oid }] of Object.entries(f.foreign)) {
    const id = `open_result in the chain form, with a pin holding a key outside the profile: ${kind}`;
    add(id, 'open_result', open(chainForm, pinOf(f.foreignLeaf(kind))));
    expect(id, { error: 'unsupported', why: `unsupported key type ${oid}` });
  }
  // The control: the pin as held, read.
  add('open_result in the chain form, with the pin as held', 'open_result', open(chainForm, pinOf(leafDer)));
  expect('open_result in the chain form, with the pin as held', { ok: 1 });
  // Two pins for the chain's root: the first is the one read, as the core reads it and as decide reads
  // a node's pins in both ports. The Go port read every one, so a second pin newer than the chain, or
  // one that did not read, refused a result the first accepted (S5-2).
  const newerLeaf = b64url(buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: ENDPOINT, notBefore: new Date('2026-09-20T00:00:00Z'), notAfter: DIES, label: 'parity/s5-2/newer' }));
  for (const [what, second, want] of [
    ['a newer leaf', newerLeaf, { ok: 1 }],
    ['an older leaf', olderLeaf, { ok: 1 }],
    ['a leaf that is not a certificate', 'AAAA', { ok: 1 }],
  ]) {
    const id = `open_result in the chain form, with two pins for its root: the first as held, the second ${what}`;
    add(id, 'open_result', open(chainForm, { pins: [...pinOf(leafDer).pins, ...pinOf(second).pins] }));
    expect(id, want);
  }
  add('open_result in the chain form, with two pins for its root: the first newer, the second as held', 'open_result', open(chainForm, { pins: [...pinOf(newerLeaf).pins, ...pinOf(leafDer).pins] }));
  expect('open_result in the chain form, with two pins for its root: the first newer, the second as held', { error: 'envelope_invalid', why: 'superseded leaf' });

  // A held key that does not read is the node's own state that does not read: an error of the call in
  // its reader's class (CONTRACT §5), as the core answers it. The Go port answered `does not open`,
  // which tells the peer about the host's damaged state and skips the host's audit of it (R23).
  for (const [what, pkcs8, want] of [
    ['is not base64url', heldKey.pkcs8.slice(0, 8) + '!' + heldKey.pkcs8.slice(8), { error: 'parse', why: 'not base64url' }],
    ['is not a key', 'AAAA', { error: 'parse' }],
    ['holds a key outside the profile', f.outside.Pkcs8, { error: 'unsupported', why: 'unsupported key type 1.3.101.112' }],
  ]) {
    add(`decide with a held key whose PKCS #8 ${what}`, 'decide', { now, envelope: sealed, node: { ...node, keys: [{ ...heldKey, pkcs8 }] } });
    expect(`decide with a held key whose PKCS #8 ${what}`, want);
  }

  // ── decide_chain: the pin decision alone, for a host's TLS door (N1, N2) ─────────────────────────
  //
  // The node's TLS door decided a client chain by hand and parted from `decide`: it read the removal
  // tombstone in the states decide does not, and served a conflicting leaf as a guest. decide_chain is
  // decide's own pin decision, answered for a chain proven outside an envelope. Every outcome, each
  // held whole — result and effects — to what decide answers for the same chain and node (the cases
  // above hold decide), and a case for each code it declares.
  {
    const chainOf = (leaf) => [typeof leaf === 'string' ? leaf : b64url(leaf), rootDer];
    const proven = chainOf(leafDer);
    const at = (o = {}) => ({ node: { ...node, endpoint: 'https://bharat.example/mcp', ...o }, chain: proven, now });
    const guest = (why, demote, claim = null) => ({ code: 'ok', tier: 'guest', root: rootFp, endpoint: ENDPOINT, leaf: leafDer, why, demote, address_claim: claim });
    const contact = (tier = 'contact', o = {}) => ({ code: 'ok', tier, root: rootFp, endpoint: ENDPOINT, leaf: leafDer, ...o });
    const pending = (why, endpoint = ENDPOINT, leaf = leafDer) => ({ op: 'pending', root: rootFp, endpoint, why, leaf });
    const moved = b64url(movedLeaf);
    const movedEffects = [
      { op: 'former_endpoint', root: rootFp, endpoint: ENDPOINT, at: now },
      { op: 'pin_update', root: rootFp, endpoint: MOVED, leaf: moved },
      { op: 'event', event: 'new_address', root: rootFp, endpoint: MOVED },
    ];
    const tombstone = (back, leaf = olderLeaf) => [{ root: rootFp, leaf, at: f.before(back) }];
    const sameDay = b64url(buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint: ENDPOINT, notBefore: BORN, notAfter: DIES, label: 'parity/decide-chain/same-day' }));
    const cases = [
      ['a root nobody pins', at(), guest('unknown root', false), []],
      ['a root nobody pins, at an address another root is pinned at', at({ pins: [{ root: OTHER_ROOT, endpoint: ENDPOINT, leaf: leafDer }] }), guest('unknown root', false, OTHER_ROOT), []],
      ['a root removed a second inside the tombstone window, with a newer leaf', at({ tombstones: tombstone(TOMBSTONE - 1) }), contact('pending_new_address', { forced: 'tombstone', decision: 'ask' }), [pending('returned after removal')]],
      ['a root removed exactly at the end of the tombstone window', at({ tombstones: tombstone(TOMBSTONE) }), guest('unknown root', false), []],
      ['a root removed with the leaf it presents', at({ tombstones: tombstone(60, leafDer) }), guest('unknown root', false), []],
      ['a blocked pin', at({ pins: [{ ...pinned[0], state: 'blocked' }] }), guest('blocked', true), []],
      ['a leaf older than the pinned one', at({ pins: [{ ...pinned[0], leaf: pinnedNewer }] }), guest('superseded leaf', true), []],
      ['a different leaf of the pinned one\'s notBefore', at({ pins: [{ ...pinned[0], leaf: sameDay }] }), { code: 'envelope_invalid', why: 'a different leaf with the same notBefore' }, []],
      ['the pinned leaf', at({ pins: pinned }), contact(), []],
      ['a newer leaf at the pinned endpoint', at({ pins: [{ ...pinned[0], leaf: olderLeaf }] }), contact(), [{ op: 'pin_update', root: rootFp, endpoint: ENDPOINT, leaf: leafDer }, { op: 'event', event: 'renewal', root: rootFp }]],
      ['a pending_out pin', at({ pins: [{ ...pinned[0], state: 'pending_out' }] }), contact('pending'), []],
    ];
    for (const [what, args, result, effects] of cases) {
      add(`decide_chain: ${what}`, 'decide_chain', args);
      expect(`decide_chain: ${what}`, { result, effects });
    }
    // A pin whose root is not a fingerprint is the host's damaged state, an error of the call, as in
    // decide: it came back as `address_claim: "abc"`, off the contract.
    add('decide_chain with a pin whose root is not a fingerprint', 'decide_chain', at({ pins: [{ ...pinned[0], root: 'abc' }] }));
    expect('decide_chain with a pin whose root is not a fingerprint', { error: 'bad_request', why: 'node.pins[0].root is not a fingerprint' });
    // Another endpoint, under auto and under ask, and a pending_out pin that moved under ask: the
    // new-address rule comes before the pending_out one.
    const movedAt = (o, pins = pinned) => ({ ...at({ pins, ...o }), chain: chainOf(movedLeaf) });
    const movedTo = (tier, o = {}) => ({ code: 'ok', tier, root: rootFp, endpoint: MOVED, leaf: moved, ...o });
    for (const [what, args, result, effects] of [
      ['the pinned root at another endpoint, under auto', movedAt({ accept_new_hosts: 'auto' }), movedTo('contact'), movedEffects],
      ['the pinned root at another endpoint, under ask', movedAt({ accept_new_hosts: 'ask' }), movedTo('pending_new_address', { decision: 'ask' }), [pending('ask', MOVED, moved)]],
      ['a pending_out pin at another endpoint, under ask', movedAt({ accept_new_hosts: 'ask' }, [{ ...pinned[0], state: 'pending_out' }]), movedTo('pending_new_address', { decision: 'ask' }), [pending('ask', MOVED, moved)]],
      // N1's state B, which is the owner's question (SPEC §5.3 reads a removal tombstone only where no
      // pin stands; the plan's (owner) item): a pin re-added while the tombstone stands, and a newer
      // leaf at another endpoint under auto. The port follows the seed, which follows the SPEC: the pin
      // decides and the tombstone is not read. This fixes today's answer, so a change is a decision.
      ['a pin and a removal tombstone for one root, at another endpoint under auto (N1, state B)', movedAt({ accept_new_hosts: 'auto', tombstones: tombstone(60) }), movedTo('contact'), movedEffects],
    ]) {
      add(`decide_chain: ${what}`, 'decide_chain', args);
      expect(`decide_chain: ${what}`, { result, effects });
    }
    // What the chain and the arguments are.
    for (const [what, args, want] of [
      ['a chain of the leaf alone', { ...at(), chain: [leafDer] }, { result: { code: 'envelope_invalid', why: 'chain rule 1: chain of 1' }, effects: [] }],
      ['a chain past its leaf\'s notAfter', { ...at(), now: '2028-01-01T00:00:00Z' }, { result: { code: 'envelope_invalid', why: 'chain rule 4: leaf outside its validity' }, effects: [] }],
      ['a chain member that is not base64url', { ...at(), chain: ['!!!', rootDer] }, { error: 'parse', why: 'not base64url' }],
      ['a chain that is not a list', { ...at(), chain: leafDer }, { error: 'bad_request', why: 'chain is required' }],
      ['a now that is not an instant', { ...at(), now: 'soon' }, { error: 'parse' }],
      ['no node', { chain: proven, now }, { error: 'bad_request', why: 'node is required' }],
      ['no chain', { node, now }, { error: 'bad_request', why: 'chain is required' }],
      ['no now', { node, chain: proven }, { error: 'bad_request', why: 'now is required' }],
      ['a node with no endpoint', { ...at(), node: { ...node, endpoint: undefined } }, { error: 'bad_request', why: 'node.endpoint is required' }],
      ['a pinned leaf holding a key outside the profile', at({ pins: [{ ...pinned[0], leaf: f.foreignLeaf('Ed25519 with a NULL') }] }), { error: 'unsupported' }],
      ['a pinned leaf that does not read', at({ pins: [{ ...pinned[0], leaf: 'AAAA' }] }), { error: 'parse' }],
    ]) {
      add(`decide_chain with ${what}`, 'decide_chain', args);
      expect(`decide_chain with ${what}`, want);
    }
  }
}
