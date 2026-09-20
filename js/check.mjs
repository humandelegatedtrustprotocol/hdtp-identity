// Proves Appendix B through a port (the Wasm bindings by default): checks that
// every 2.0 vector does what the spec says. Reads the vectors from SPEC.md itself, as the seed's
// check.mjs does, so the bytes in the document are the bytes proven — by a second implementation.
import { readFileSync, existsSync } from 'node:fs';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { b64url, fromB64url } from '../../pact-protocol/vectors/lib/keys.mjs';
import { makePort, portFromArgv } from './port.mjs';
import { makeDefender } from './defender.mjs';

const port = await makePort(portFromArgv());
if (!port) { console.log('the Go port is not built (go/bin/pact-identity-go)'); process.exit(2); }
const d = makeDefender(port);
console.log(`port: ${port.kind} ${JSON.stringify(port.call('version', {}))}`);

const specPath = new URL('../../pact-protocol/SPEC.md', import.meta.url);
const spec = readFileSync(specPath, 'utf8');
const appendixB = spec.slice(spec.indexOf('## Appendix B'), spec.indexOf('*End of PACT'));
const blocks = [...appendixB.matchAll(/```json\n([\s\S]*?)\n```/g)].map((m) => JSON.parse(m[1]));
if (blocks.length < 1) throw new Error('Appendix B has no vector blocks');
const [v2] = blocks;

let failures = 0, checks = 0;
const ok = (cond, what) => { checks++; if (!cond) { failures++; console.log('  FAIL ' + what); } };
const spkiOfPkcs8 = (hexKey) => fromB64url(port.call('public_key', { pkcs8: b64url(Buffer.from(hexKey, 'hex')) }).spki);

if (!v2) {
  console.log('no 2.0 block in Appendix B yet');
} else {
  const file = new URL('../../pact-protocol/vectors/pact-2.0-vectors.json', import.meta.url);
  if (existsSync(file)) ok(JSON.stringify(JSON.parse(readFileSync(file, 'utf8'))) === JSON.stringify(v2), 'SPEC.md carries the generated vectors unchanged');
  const der = Object.fromEntries(Object.entries(v2.certificates).map(([k, c]) => [k, Buffer.from(c.der_hex, 'hex')]));
  const chainOf = (names) => names.map((n) => der[n]);

  console.log('certificates parse under OpenSSL as well');
  for (const [name, bytes] of Object.entries(der)) {
    const c = new X509Certificate(bytes), mine = d.parseCert(bytes);
    ok(c.subject.includes(mine.subject), `${name}: subject`);
    ok(c.ca === mine.ca, `${name}: cA`);
    // Asked of OpenSSL's view, not of ours: `if (mine.uris.length)` takes the condition from the
    // value under test, so a port that dropped its SANs made the assertion vanish rather than fail.
    if (c.subjectAltName) ok(mine.uris.length > 0 && c.subjectAltName.includes('URI:' + mine.uris[0]), `${name}: subjectAltName`);
    ok(Math.abs(c.validFromDate - Date.parse(mine.not_before)) < 1000, `${name}: notBefore`);
    ok(mine.profile_error === null && mine.kind === (name.startsWith('root') ? 'root' : 'leaf'), `${name}: in the profile as a ${mine.kind}`);
    if (name.startsWith('leaf_a')) ok(c.checkIssued(new X509Certificate(der.root_a)) && c.verify(new X509Certificate(der.root_a).publicKey), `${name}: issued and verified by root_a per OpenSSL`);
    if (name === 'leaf_b') ok(c.checkIssued(new X509Certificate(der.root_b)) && c.verify(new X509Certificate(der.root_b).publicKey), `${name}: issued and verified by root_b per OpenSSL`);
    ok(bytes.length <= 4096, `${name}: under 4 KiB`);
  }

  console.log('chain cases (§14.2)');
  for (const c of v2.chain_cases) {
    const r = d.validateChain(chainOf(c.chain), { now: new Date(c.now), expectedRoot: c.expected_root, expectedEndpoint: c.expected_endpoint });
    if (c.expect === 'accept') ok(r.ok, `${c.name}: expected accept, got rule ${r.rule} (${r.reason})`);
    else ok(!r.ok && r.rule === c.rule, `${c.name}: expected refusal by rule ${c.rule}, got ${r.ok ? 'accept' : 'rule ' + r.rule + ' (' + r.reason + ')'}`);
    console.log(`  ${c.name}: ${r.ok ? 'accepted' : 'refused by rule ' + r.rule}`);
  }

  console.log('newest leaf (§14.3)');
  for (const c of v2.newest_leaf_cases) {
    const got = d.compareLeaves(der[c.pinned], der[c.presented]);
    ok(got === c.expect, `${c.pinned} vs ${c.presented}: expected ${c.expect}, got ${got}`);
    console.log(`  ${c.pinned} then ${c.presented}: ${got}`);
  }

  console.log('certificate_renewed (§14.4)');
  for (const c of v2.certificate_renewed_cases) {
    const pinned = d.parseCert(der[c.pinned_leaf]);
    const r = d.followRenewed(c.answer, 'sha256:' + pinned.aki, der[c.pinned_leaf], c.dialed, new Date(c.now));
    ok(r.follow === (c.expect === 'follow'), `${c.name}: expected ${c.expect}, got ${JSON.stringify(r)}`);
    console.log(`  ${c.name}: ${r.follow ? 'followed' : 'discarded'}${r.why ? ' (' + r.why + ')' : ''}`);
  }

  console.log('v2 envelopes (§13)');
  for (const v of v2.envelopes) {
    const recipientLeaf = d.parseCert(der[v.recipient_chain[0]]);
    const recipientPriv = createPrivateKey({ key: Buffer.from(v2.leaf_keys_pkcs8_hex[v.recipient_chain[0]], 'hex'), format: 'der', type: 'pkcs8' });
    const aad = fromB64url(v.protected), enc = fromB64url(v.enc), ct = fromB64url(v.ct);
    const header = JSON.parse(aad.toString());
    ok(Object.keys(header).sort().join(',') === 'cty,exp,kid,msg_id,suite,ts,v', `${v.name}: header members`);
    ok(header.v === 2 && header.suite === v.suite && header.suite === port.call('suite_for', { spki: recipientLeaf.spki }).suite, `${v.name}: version and suite`);
    ok(header.kid === recipientLeaf.fingerprint, `${v.name}: kid is the recipient leaf key`);
    ok(createPublicKey(recipientPriv).export({ format: 'der', type: 'spki' }).equals(fromB64url(recipientLeaf.spki)), `${v.name}: the recipient key is the leaf's`);
    let plaintext = null;
    try { plaintext = d.open(v.suite, recipientPriv, null, Buffer.from('PACT-SEAL-v2'), aad, enc, ct); } catch (e) { ok(false, `${v.name}: open threw ${e.message}`); }
    ok(plaintext && plaintext.toString('hex') === v.plaintext_hex, `${v.name}: plaintext`);
    if (plaintext) {
      const body = JSON.parse(plaintext.toString());
      const senderLeaf = d.parseCert(der[v.sender_chain[0]]);
      if (v.form === 'leaf') {
        ok(Object.keys(body).sort().join(',') === 'leaf,method,params', `${v.name}: small form carries leaf, method, params`);
        ok(body.leaf === senderLeaf.fingerprint, `${v.name}: leaf names the sender's held leaf`);
        ok(d.verify(fromB64url(senderLeaf.spki), Buffer.concat([aad, enc, ct]), fromB64url(v.sig)), `${v.name}: signature under the held leaf's key`);
        ok(ct.length < 400, `${v.name}: small form stays small (${ct.length} bytes sealed)`);
      } else {
        ok(Object.keys(body).sort().join(',') === 'chain,method,params', `${v.name}: full form carries chain, method, params`);
        const chain = body.chain.map(fromB64url);
        const r = d.validateChain(chain, { now: new Date(v2.now) });
        ok(r.ok, `${v.name}: chain inside validates`);
        ok(r.ok && chain[0].equals(der[v.sender_chain[0]]), `${v.name}: chain inside is the sender's`);
        ok(r.ok && d.verify(r.leafSpki, Buffer.concat([aad, enc, ct]), fromB64url(v.sig)), `${v.name}: signature under the chain's leaf key`);
      }
      // The port re-seals the same plaintext from the vector's ephemeral seed and lands on the same bytes.
      const { createHash } = await import('node:crypto');
      const eph = createHash('sha256').update('pact-2.0-vectors/ephemeral/' + v.name).digest();
      const sender = v2.leaf_keys_pkcs8_hex[v.sender_chain[0]];
      const again = port.call('seal_request', { recipient_leaf: b64url(der[v.recipient_chain[0]]), sender_pkcs8: b64url(Buffer.from(sender, 'hex')), form: v.form, sender_chain: v.sender_chain.map((n) => b64url(der[n])), method: body.method, params: body.params, msg_id: header.msg_id, ts: header.ts, exp: header.exp, ephemeral_seed: b64url(eph) });
      ok(again.protected === v.protected && again.enc === v.enc && again.ct === v.ct, `${v.name}: re-sealed from the seed, enc and ct reproduce`);
    }
    console.log(`  ${v.name}: ${plaintext ? 'opened' : 'closed'}${v.form === 'leaf' ? ' (by reference)' : ''}`);
  }

  // §2.1, through the boundary rather than through a library function: the port is asked for the
  // salt and for each seed, so what passes is what a caller of the contract gets, not what the
  // crate computes internally.
  console.log('derivation (§2.1)');
  const seen = new Map();
  for (const x of v2.derivation ?? []) {
    ok(port.call('prf_salt', {}).salt === x.salt, `${x.label}: the port's own salt is the vector's`);
    const got = port.call('derive_seed', { prf: x.prf, info: x.info });
    ok(got.seed === x.seed, `${x.label}: HKDF-SHA256(prf, empty salt, "${x.info}", 32)`);
    if (x.alg) {
      const key = port.call('key_from_seed', { alg: x.alg, seed: x.seed });
      ok(key.spki === x.spki, `${x.label}: the key the seed makes`);
      ok(key.fingerprint === x.fingerprint, `${x.label}: the identity that key is`);
    }
    ok(!seen.has(got.seed), `${x.label}: a different info gives a different seed`);
    seen.set(got.seed, x.info);
    console.log(`  ${x.label} (${x.info}): ${x.fingerprint ?? 'seed only'}`);
  }
  ok((v2.derivation ?? []).length >= 3, 'all three info strings are covered');
  // The refusals are the point of specifying the info strings at all — a typo would otherwise
  // succeed and hand back a key belonging to nobody.
  for (const [why, args] of [
    ['an info string that is not one of the three', { prf: v2.derivation[0].prf, info: 'pact/root/2' }],
    ['the wrong case in a domain separator', { prf: v2.derivation[0].prf, info: 'pact/Root/1' }],
  ]) ok(port.call('derive_seed', args).error === 'bad_request', `derive_seed refuses ${why}`);
}

console.log(`${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
