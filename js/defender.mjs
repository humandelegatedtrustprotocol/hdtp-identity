// The defender on a port: the seed library's shapes (`validateChain`, `open`, `seal`, `decodeCard`,
// `makeNode` … `receive`) backed by a pact-identity port. Node state stays in JavaScript exactly as
// the seed keeps it; `receive` hands it to the port's pure `decide` and applies the effects it returns.
import { createPublicKey } from 'node:crypto';
import { b64url, fromB64url, pkcs8Of, spkiOf, fingerprint } from '../../pact-protocol/vectors/lib/keys.mjs';
import { parse } from '../../pact-protocol/vectors/lib/x509.mjs';

const iso = (d) => new Date(d).toISOString();

export function makeDefender(port) {
  const call = (name, args) => port.call(name, args);
  const must = (r) => { if (r && r.error) throw new Error(`${r.error}: ${r.why}`); return r; };

  function validateChain(chainDer, { now, expectedRoot, expectedEndpoint } = {}) {
    const r = call('validate_chain', { chain: chainDer.map(b64url), now: iso(now ?? Date.now()), expected_root: expectedRoot, expected_endpoint: expectedEndpoint });
    if (r.error) return { ok: false, rule: 1, reason: r.why };
    if (!r.ok) return r;
    return { ok: true, leafKey: createPublicKey({ key: fromB64url(r.leaf_spki), format: 'der', type: 'spki' }), leafSpki: fromB64url(r.leaf_spki), rootFingerprint: r.root_fingerprint, endpoint: r.endpoint, notBefore: r.not_before, notAfter: r.not_after };
  }
  const open = (suite, priv, pub, info, aad, enc, ct) => fromB64url(must(call('hpke_open', { suite, recipient_pkcs8: b64url(pkcs8Of(priv)), recipient_spki: b64url(spkiOf(pub)), info: Buffer.from(info).toString(), aad: b64url(aad), enc: b64url(enc), ct: b64url(ct) })).plaintext);
  const sealWith = (suite, pub, info, aad, plaintext, seed) => {
    const r = must(call('hpke_seal', { suite, recipient_spki: b64url(spkiOf(pub)), info: Buffer.from(info).toString(), aad: b64url(aad), plaintext: b64url(plaintext), ephemeral_seed: seed ? b64url(seed) : undefined }));
    return { enc: fromB64url(r.enc), ct: fromB64url(r.ct) };
  };
  // Production sealing takes no seed: a sixth argument is dropped on the floor here, as the core's API has no place for it.
  const seal = (suite, pub, info, aad, plaintext) => sealWith(suite, pub, info, aad, plaintext, undefined);
  const sealDeterministic = (suite, pub, info, aad, plaintext, seed) => sealWith(suite, pub, info, aad, plaintext, seed);
  function decodeCard(text) {
    const r = call('card_decode', { vcard: text, now: iso(Date.now()) });
    if (r.error) return { error: r.error, why: r.why };
    return { ...r, cert: fromB64url(r.cert), leaf: r.leaf };
  }
  const compareLeaves = (a, b) => must(call('compare_leaves', { pinned: b64url(a), presented: b64url(b) })).order;
  const parseCert = (der) => must(call('parse_certificate', { der: b64url(der) }));
  const verify = (spki, data, sig) => must(call('verify', { spki: b64url(spki), data: b64url(data), sig: b64url(sig) })).valid;
  const followRenewed = (answer, pinnedRoot, pinnedLeaf, dialed, now) => must(call('follow_renewed', { answer, pinned_root: pinnedRoot, pinned_leaf: b64url(pinnedLeaf), dialed, now: iso(now) }));

  // ── the node, state kept as the seed keeps it ─────────────────────────────────
  function slot(leafKey, leafDer) {
    return { key: leafKey, kid: fingerprint(leafKey.pub), leafDer, notAfter: parse(leafDer).notAfter, current: true };
  }
  function makeNode({ path, leafKey, chain, now, acceptNewHosts = 'auto' }) {
    return { path, endpoint: parse(chain[0]).uris[0], now, acceptNewHosts, chain, keys: [slot(leafKey, chain[0])], former: new Set(), pins: new Map(), tombstones: new Map(), formerEndpoints: [], seen: new Set(), events: [], pending: [] };
  }
  function renew(node, leafKey, chain) {
    for (const k of node.keys) k.current = false;
    node.keys.push(slot(leafKey, chain[0]));
    node.chain = chain; node.endpoint = parse(chain[0]).uris[0];
  }
  function forgetKeysPast(node) {
    for (const k of [...node.keys]) if (!k.current && node.now > k.notAfter) { node.keys.splice(node.keys.indexOf(k), 1); node.former.add(k.kid); }
  }
  function pin(node, root, { endpoint, leafDer, state = 'active' }) { node.pins.set(root, { endpoint, leafDer, state }); }
  function removeContact(node, root) {
    const p = node.pins.get(root);
    if (p) { node.tombstones.set(root, { leafDer: p.leafDer, at: node.now }); node.pins.delete(root); }
  }
  function receive(node, envelope, { siblings = [] } = {}) {
    const input = {
      now: iso(node.now),
      envelope: { protected: envelope.protected, enc: envelope.enc, ct: envelope.ct, sig: envelope.sig },
      node: {
        endpoint: node.endpoint, accept_new_hosts: node.acceptNewHosts, chain: node.chain.map(b64url),
        keys: node.keys.map((k) => ({ kid: k.kid, leaf: b64url(k.leafDer), pkcs8: b64url(pkcs8Of(k.key.priv)), current: k.current })),
        former: [...node.former], sibling_kids: siblings.flatMap((s) => s.keys.map((k) => k.kid)),
        pins: [...node.pins].map(([root, p]) => ({ root, endpoint: p.endpoint, leaf: b64url(p.leafDer), state: p.state })),
        tombstones: [...node.tombstones].map(([root, t]) => ({ root, leaf: b64url(t.leafDer), at: iso(t.at) })),
        former_endpoints: node.formerEndpoints.map((f) => ({ root: f.root, endpoint: f.endpoint, at: iso(f.at) })),
        seen: [...node.seen],
      },
    };
    const out = must(call('decide', input));
    for (const e of out.effects) {
      switch (e.op) {
        case 'seen': node.seen.add(e.msg_id); break;
        case 'pin_update': { const p = node.pins.get(e.root); if (p) { p.endpoint = e.endpoint; p.leafDer = fromB64url(e.leaf); } break; }
        case 'former_endpoint': node.formerEndpoints.push({ root: e.root, endpoint: e.endpoint, at: Date.parse(e.at) }); break;
        case 'event': node.events.push(e.endpoint === undefined ? { event: e.event, root: e.root } : { event: e.event, root: e.root, endpoint: e.endpoint }); break;
        case 'pending': node.pending.push({ root: e.root, endpoint: e.endpoint, why: e.why }); break;
        default: throw new Error('unknown effect ' + e.op);
      }
    }
    const r = { ...out.result };
    if ('address_claim' in r) { r.addressClaim = r.address_claim; delete r.address_claim; }
    return r;
  }

  return { validateChain, open, seal, sealDeterministic, decodeCard, compareLeaves, parseCert, verify, followRenewed, makeNode, renew, forgetKeysPast, pin, removeContact, receive, call };
}
