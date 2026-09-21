// The live adapter against a faithful fake: an HTTP endpoint whose defender is the seed
// library's own receiving node, so every verdict the adapter prints is one the seed
// would print. `node --test js/live.test.mjs`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { seed, ed25519FromSeed, b64url } from '../../pact-protocol/vectors/lib/keys.mjs';
import { buildRoot, buildLeaf } from '../../pact-protocol/vectors/lib/x509.mjs';
import { encodeCard } from '../../pact-protocol/vectors/lib/card.mjs';
import { makeNode, receive } from '../../pact-protocol/vectors/lib/envelope.mjs';
import { readFileSync } from 'node:fs';
import { runLive, answerCode, scenarios } from './live.mjs';
import { load } from './index.mjs';

const H = 3_600_000, D = 86_400_000;

function fakeNode(port) {
  const now = Date.now();
  const endpoint = `http://127.0.0.1:${port}/alina`;
  const root = ed25519FromSeed(seed('live-test/root')), host = ed25519FromSeed(seed('live-test/host'));
  const ROOT = buildRoot({ cn: 'Alina', key: root, notBefore: new Date(now - D), label: 'lt/root' });
  // The leaf names an https endpoint (the profile demands it); the fake listens on http and is dialed by its own address.
  const LEAF = buildLeaf({ cn: 'Alina', rootCn: 'Alina', root, hostKey: host, endpoint: 'https://alina.example/mcp', notBefore: new Date(now - H), notAfter: new Date(now + 365 * D), label: 'lt/leaf' });
  const node = makeNode({ path: '/alina', leafKey: host, chain: [LEAF, ROOT], now });
  const card = encodeCard({ fn: 'Alina', cert: LEAF, seal: 'required' });
  return { node, card, endpoint, LEAF, ROOT, host };
}

/**
 * What an honest receiver answers a call it let through with: a RESULT, sealed to the caller's leaf
 * key, signed by this node's leaf, carrying this node's chain (§13.2). The fake used to answer
 * `{protected:'x',enc:'x',ct:'x',sig:'x'}` — four strings — and the driver called that "sealed", so
 * the control proved only that the fake could spell the member names.
 *
 * The seed decides; the pinned core learns who the caller was (`decide` hands back the leaf it
 * validated) and seals to that key.
 */
async function sealedResult(fake, envelope) {
  const core = await load();
  const pkcs8 = b64url(fake.host.priv.export({ format: 'der', type: 'pkcs8' }));
  const mine = core.call('parse_certificate', { der: b64url(fake.LEAF) });
  const now = new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace('.000Z', 'Z');
  const decided = core.call('decide', {
    now, envelope,
    node: { endpoint: 'https://alina.example/mcp', accept_new_hosts: 'auto', chain: [b64url(fake.LEAF), b64url(fake.ROOT)],
      keys: [{ kid: mine.fingerprint, leaf: b64url(fake.LEAF), pkcs8, current: true }],
      former: [], sibling_kids: [], pins: [], tombstones: [], former_endpoints: [], seen: [] },
  });
  assert.equal(decided.result?.code, 'ok', `the core and the seed disagree about the control: ${JSON.stringify(decided).slice(0, 200)}`);
  const caller = core.call('parse_certificate', { der: decided.result.leaf });
  const header = JSON.parse(Buffer.from(envelope.protected, 'base64url').toString());
  const sealed = core.call('seal_result', {
    recipient_spki: caller.spki, sender_pkcs8: pkcs8, form: 'chain', sender_chain: [b64url(fake.LEAF), b64url(fake.ROOT)],
    result: { status: 'pending' }, msg_id: header.msg_id, ts: Math.floor(Date.now() / 1000),
  });
  assert.ok(!sealed.error, `seal_result: ${sealed.error}: ${sealed.why}`);
  return sealed;
}

/** The fake behind an HTTP door. `answerOk` is what it sends for a call the seed let through. */
async function serve(answerOk) {
  const server = createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const fake = fakeNode(server.address().port);
  server.on('request', (req, res) => {
    if (req.method === 'GET' && req.url.endsWith('/card.vcf')) { res.setHeader('content-type', 'text/vcard'); res.end(fake.card); return; }
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', async () => {
      fake.node.now = Date.now();
      const rpc = JSON.parse(body);
      res.setHeader('content-type', 'application/json');
      // A stateless receiver: it answers the MCP handshake and hands back no session id, which is
      // how the hosted platform behaves. (The reference node keeps sessions; the driver's handshake
      // is proven against that one by aiming it there.)
      if (rpc.method === 'initialize') { res.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'seed', version: '1' } } })); return; }
      if (rpc.method !== 'tools/call') { res.statusCode = 202; res.end(); return; }
      const answer = receive(fake.node, rpc.params.arguments);
      if (answer.code === 'ok') res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: JSON.stringify(await answerOk(fake, rpc.params.arguments)) }] } }));
      else res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: answer.code, data: { code: answer.code, why: answer.why } } }));
    });
  });
  const lines = [];
  // The seed's card intake refuses an http endpoint only at the address guard, which the fake does not run; the adapter dials what it was given.
  const out = await runLive({ endpoint: fake.endpoint, fetchImpl: (u, init) => fetch(u.replace('https://alina.example/mcp', fake.endpoint), init), log: (l) => lines.push(l) });
  server.close();
  return { out, lines };
}

test('every black-box scenario is blocked by the seed node behind an HTTP door', async () => {
  const { out, lines } = await serve(sealedResult);
  assert.equal(out.reproduces, 0, lines.join('\n'));
  // A FLOOR, not a count. This was `=== 10`, and it locked a stale number in the day the live
  // battery grew to 26 (2026-09-18): the test failed from then on, and nothing ran it — its only
  // runner was a CI job that never got past its first step. What a number here is for is noticing
  // the battery SHRINK, so it may only ever be raised.
  assert.ok(out.results.length >= 28, `the live battery ran ${out.results.length} scenarios; it has run 28`);
  assert.equal(out.unreached, 0, 'every scenario reached a PACT answer');
  // The total comes from the seed, so this cannot lock a stale number in: what it asserts is that
  // the two add up.
  assert.ok(out.seedScenarios >= out.results.length, 'the seed has at least the scenarios a live run covers');
  assert.ok(out.results.every((r) => r.verdict === 'blocked'), lines.join('\n'));
});

// The control is the one call that must get THROUGH, and it was judged by the look of its answer.
// This is the fake as it was until 2026-09-21: four strings where an envelope should be.
test('a control answered with something that only looks sealed is not a control that passed', async () => {
  const { out, lines } = await serve(async () => ({ protected: 'x', enc: 'x', ct: 'x', sig: 'x' }));
  const control = out.results.at(-1);
  assert.equal(control.got, 'sealed', 'the cheap reading still calls it sealed, which is why the control cannot stop there');
  assert.equal(control.verdict, 'CONTROL UNOPENED', lines.join('\n'));
  assert.equal(out.controlUnopened, 1);
  assert.ok(out.results.slice(0, -1).every((r) => r.verdict === 'blocked'), 'nothing else changes');
});

// Two drivers, one rule: the Rust one opens its control's answer too, and gives the failure the same name.
test('the Rust driver opens its control as this one does', () => {
  const rust = readFileSync(new URL('../crates/pact/src/vectors.rs', import.meta.url), 'utf8');
  const js = readFileSync(new URL('./live.mjs', import.meta.url), 'utf8');
  for (const [name, src] of [['crates/pact/src/vectors.rs', rust], ['js/live.mjs', js]]) {
    assert.ok(src.includes('CONTROL UNOPENED'), `${name} has no verdict for a control whose answer does not open`);
  }
  assert.match(rust, /control_opened\(&raw, &host_m,/, 'the Rust control is no longer opened with the key the driver holds');
  assert.match(js, /await controlOpened\(first\.text,/, 'the JS control is no longer opened');
});

test('answerCode reads every shape an endpoint answers in', () => {
  assert.equal(answerCode({ error: { code: -32000, data: { code: 'chain_required' } } }), 'chain_required');
  assert.equal(answerCode({ result: { content: [{ text: JSON.stringify({ protected: 'a', enc: 'b', ct: 'c', sig: 'd' }) }] } }), 'sealed');
  assert.equal(answerCode({ result: { content: [{ text: JSON.stringify({ error: { code: 'envelope_invalid' } }) }] } }), 'envelope_invalid');
  // …and the ones the reference node answers in, which this read none of until 2026-09-20: an
  // event stream, a `code` in the tool's own text, and raw text that is no JSON at all.
  assert.equal(answerCode('event: message\ndata: {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"data":{"code":"envelope_invalid"}}}\n\n'), 'envelope_invalid');
  assert.equal(answerCode({ result: { content: [{ text: JSON.stringify({ code: 'chain_required' }) }] } }), 'chain_required');
  assert.ok(answerCode('Bad Request: no session').startsWith('unknown:not-json'));
});


/**
 * Two drivers aim this battery: this one, and `pact vectors intrude` in Rust. They were written in
 * one commit and differed on day one — 27 scenarios against 26, a control in one and not the other,
 * three header forgeries sealed properly here and rewritten-after-sealing there — and each was then
 * taught things the other was not (the MCP handshake reached the Rust driver and not this one, which
 * went on to report 27 of 27 intrusions against the reference node). So the two lists are held to
 * each other by name and ORDER, read out of the Rust source as text.
 */
test('the Rust driver runs the same scenarios, in the same order', () => {
  const rust = readFileSync(new URL('../crates/pact/src/vectors.rs', import.meta.url), 'utf8');
  const body = rust.slice(rust.indexOf('pub fn intrude('));
  const constant = (name) => Number(new RegExp(`const ${name}: i64 = (\\d+);`).exec(body)?.[1]);
  const seconds = constant('WINDOW') + constant('MARGIN');
  const names = [...body.matchAll(/\brun\(\s*(?:&format!\(\s*)?"([^"]+)"/g)].map((m) => m[1].replace('{}', String(seconds)));
  const mine = scenarios({ targetLeaf: fakeNode(1).LEAF }).map((s) => s.name);
  assert.ok(names.length >= 28, `read ${names.length} scenario names out of the Rust driver; the extraction has stopped seeing it`);
  assert.deepEqual(names, mine);
});

/**
 * ...and the same EXPECTED CODE, which the name check above cannot see.
 *
 * Holding names and order still let the two drivers disagree about what each scenario should be
 * answered with: change the Rust `expect` for the small form from `chain_required` to
 * `envelope_invalid` and every gate stayed green, because only a live run against a real node would
 * notice, as a REPRODUCES with no obvious cause. The last argument of each `run(` call is that code,
 * read by walking the call's arguments at depth zero -- which survives a comma inside
 * `&format!("...{}...", WINDOW + MARGIN)` and rustfmt reflowing a call across lines.
 */
test('the Rust driver expects the same answer for each scenario', () => {
  const rust = readFileSync(new URL('../crates/pact/src/vectors.rs', import.meta.url), 'utf8');
  const body = rust.slice(rust.indexOf('pub fn intrude('));
  const consts = Object.fromEntries(
    [...body.matchAll(/const ([A-Z_]+): &str = "([^"]+)";/g)].map((m) => [m[1], m[2]]),
  );
  /** The top-level arguments of one `run(...)` call. */
  const args = (text) => {
    const out = [];
    let depth = 0, quoted = false, start = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quoted) { if (c === '\\') i++; else if (c === '"') quoted = false; continue; }
      if (c === '"') quoted = true;
      else if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') depth--;
      else if (c === ',' && depth === 0) { out.push(text.slice(start, i).trim()); start = i + 1; }
    }
    out.push(text.slice(start).trim());
    return out;
  };
  const expects = [...body.matchAll(/\brun\(([\s\S]*?)\)\?;/g)].map((m) => {
    // rustfmt writes a TRAILING comma when it reflows a call across lines, which leaves an empty
    // final argument; two of the 28 are written that way.
    const last = args(m[1]).filter((a) => a !== '').at(-1);
    const literal = /^"([^"]*)"$/.exec(last);
    return literal ? literal[1] : (consts[last] ?? `UNRESOLVED(${last})`);
  });
  assert.ok(expects.length >= 28, `read ${expects.length} expected codes out of the Rust driver`);
  assert.deepEqual(expects.filter((e) => e.startsWith('UNRESOLVED')), [], 'every expected code must resolve to a string');
  assert.deepEqual(expects, scenarios({ targetLeaf: fakeNode(1).LEAF }).map((s) => s.expect));
});

test('the control is last, because after it the attacker is no stranger', () => {
  const list = scenarios({ targetLeaf: fakeNode(1).LEAF });
  const controls = list.filter((s) => s.expect === 'sealed');
  assert.equal(controls.length, 1, 'exactly one scenario must get THROUGH: a receiver that refuses everything fails it');
  assert.equal(list.at(-1), controls[0]);
});

test('the attacker is new every run', () => {
  // On her ROOT, not on a signature. This asserted `notEqual` over `envelope.sig`, which is a
  // signature covering the HPKE ephemeral public key — fresh on every seal whatever her long-term
  // keys are. So it passed with the fixed seed it was written to catch: the mutation check I owed
  // this test and did not do (2026-09-20). Her root is the thing that must differ, because the
  // control leaves her PENDING on the target and a repeat run must arrive as a stranger.
  const rootOf = () => scenarios({ targetLeaf: fakeNode(1).LEAF }).at(-1).attacker;
  assert.notEqual(rootOf(), rootOf());
});
