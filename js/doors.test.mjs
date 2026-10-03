// A host's two doors, one decision (N1, N2): `decide` on a sealed call and `decide_chain` on the same
// chain proven at the TLS layer, against the same node state, decide the pins alike, in each port.
//
// The node's TLS door decided a client chain by hand, and parted from the sealed door: it read the
// removal tombstone in the states `decide` does not, and served a conflicting leaf as a guest.
// `decide_chain` is `decide`'s own pin decision, answered on its own; this holds the two to each other
// over every outcome, where the parity cases hold each to its own expected answer. A change inside the
// shared decision moves both doors together and cannot show here — the parity expectations catch that;
// what this catches is either door mapping the decision differently.
//
// The call is a guest's `request_contact` carrying the chain's own card, so what `decide` adds per call
// is fixed: a guest is answered as one, a pending_out pin's call waits (`pending_approval`), and every
// other outcome is the tier. `node --test js/doors.test.mjs` (the Go adapter must be built).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makePort } from './port.mjs';
import { fixtures } from './cases/fixtures.mjs';
import { b64url } from '../../hdtp-spec/vectors/lib/keys.mjs';
import { buildLeaf } from '../../hdtp-spec/vectors/lib/x509.mjs';
import { encodeCard } from '../../hdtp-spec/vectors/lib/card.mjs';
import { ENDPOINTS, BORN, DIES } from './cast.mjs';

const wasm = await makePort('wasm');
const go = await makePort('go');
const f = fixtures({ wasm, go });
const { now, node, pinned, rootKey, hostKey, ENDPOINT, rootFp, leafDerBytes, rootDerBytes, olderLeaf } = f;

const leafOf = (endpoint, notBefore, label) =>
  buildLeaf({ cn: 'Alina Rao', rootCn: 'Alina Rao', root: rootKey, hostKey, endpoint, notBefore, notAfter: DIES, label });
const moved = leafOf(ENDPOINTS.alinaMoved, new Date('2026-09-10T00:00:00Z'), 'doors/moved');
const newer = b64url(leafOf(ENDPOINT, new Date('2026-09-10T00:00:00Z'), 'doors/newer'));
const sameDay = b64url(leafOf(ENDPOINT, BORN, 'doors/same-day'));
const OTHER = 'sha256:' + 'B'.repeat(43);
const elsewhere = { ...node, endpoint: 'https://bharat.example/mcp' };
const tomb = (back, leaf = olderLeaf) => [{ root: rootFp, leaf, at: f.before(back) }];
const pin = (o = {}) => [{ ...pinned[0], ...o }];

// [what, the leaf the chain presents, the node]: every outcome of the pin decision.
const SCENARIOS = [
  ['a root nobody pins', leafDerBytes, elsewhere],
  ['a root nobody pins, at an address another root holds', leafDerBytes, { ...elsewhere, pins: [{ root: OTHER, endpoint: ENDPOINT, leaf: b64url(leafDerBytes) }] }],
  ['a removed root returning with a newer leaf', leafDerBytes, { ...elsewhere, tombstones: tomb(60) }],
  ['a removed root returning past the window', leafDerBytes, { ...elsewhere, tombstones: tomb(31 * 86400) }],
  ['a blocked pin', leafDerBytes, { ...elsewhere, pins: pin({ state: 'blocked' }) }],
  ['a leaf older than the pinned one', leafDerBytes, { ...elsewhere, pins: pin({ leaf: newer }) }],
  ['a different leaf of the pinned one\'s date', leafDerBytes, { ...elsewhere, pins: pin({ leaf: sameDay }) }],
  ['the pinned leaf', leafDerBytes, { ...elsewhere, pins: pinned }],
  ['a newer leaf at the pinned endpoint', leafDerBytes, { ...elsewhere, pins: pin({ leaf: olderLeaf }) }],
  ['a pending_out pin', leafDerBytes, { ...elsewhere, pins: pin({ state: 'pending_out' }) }],
  ['another endpoint under auto', moved, { ...elsewhere, accept_new_hosts: 'auto', pins: pinned }],
  ['another endpoint under ask', moved, { ...elsewhere, accept_new_hosts: 'ask', pins: pinned }],
  ['a pending_out pin at another endpoint under ask', moved, { ...elsewhere, accept_new_hosts: 'ask', pins: pin({ state: 'pending_out' }) }],
  ['a pin and a tombstone, at another endpoint under auto', moved, { ...elsewhere, accept_new_hosts: 'auto', pins: pinned, tombstones: tomb(60) }],
];

const withoutSeen = (effects) => effects.filter((e) => e.op !== 'seen');
const MEMBERS = ['root', 'endpoint', 'leaf', 'forced', 'decision', 'why', 'demote', 'address_claim'];

for (const [kind, port] of [['wasm', wasm], ['go', go]]) {
  test(`${kind}: decide and decide_chain decide the pins alike, over every outcome`, () => {
    assert.ok(port, `the ${kind} port is not built`);
    const reached = new Set();
    SCENARIOS.forEach(([what, leaf, state], i) => {
      const chain = [leaf, rootDerBytes];
      const card = encodeCard({ fn: 'Alina Rao', cert: leaf });
      const envelope = f.request({ senderChain: chain, params: { name: 'request_contact', arguments: { card } }, msgId: `doors-${i}` });
      const sealed = port.call('decide', { now, envelope, node: state });
      const tls = port.call('decide_chain', { node: state, chain: chain.map(b64url), now });
      assert.equal(sealed.error, undefined, `${what}: decide failed: ${sealed.why}`);
      assert.equal(tls.error, undefined, `${what}: decide_chain failed: ${tls.why}`);
      const [s, t] = [sealed.result, tls.result];
      if (t.code === 'envelope_invalid') {
        reached.add('refused');
        assert.deepEqual(s, t, `${what}: a refusal, the same`);
        assert.deepEqual(tls.effects, [], what);
        return;
      }
      reached.add(t.tier);
      if (t.tier === 'pending') {
        // The pin is pending_out, and request_contact is not one of the pending tier's calls: the call
        // waits, and the pin's moves are applied all the same. The answer names what the signature
        // proved, as decide_chain names it, so a host can seal the refusal back (lead 2 of the
        // port-parity audit): the root, the address and the leaf, and the envelope's form and msg_id.
        assert.deepEqual(s, { code: 'pending_approval', root: t.root, endpoint: t.endpoint, leaf: t.leaf, form: 'chain', msg_id: `doors-${i}` }, what);
      } else {
        assert.equal(s.code, 'ok', what);
        assert.equal(s.tier, t.tier, what);
        for (const m of MEMBERS) assert.deepEqual(s[m], t[m], `${what}: ${m}`);
      }
      assert.deepEqual(withoutSeen(sealed.effects), tls.effects, `${what}: effects`);
    });
    // Every outcome of the pin decision was reached, or the test says less than it claims.
    assert.deepEqual([...reached].sort(), ['contact', 'guest', 'pending', 'pending_new_address', 'refused']);
  });
}
