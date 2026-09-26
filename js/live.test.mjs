// The live adapter against a faithful fake: an HTTP endpoint whose defender is the seed
// library's own receiving node, so every verdict the adapter prints is one the seed
// would print. `node --test js/live.test.mjs`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { b64url } from '../../pact-protocol/vectors/lib/keys.mjs';
import { buildRoot, buildLeaf } from '../../pact-protocol/vectors/lib/x509.mjs';
import { encodeCard } from '../../pact-protocol/vectors/lib/card.mjs';
import { makeNode, receive } from '../../pact-protocol/vectors/lib/envelope.mjs';
import { readFileSync } from 'node:fs';
import { runLive, answerCode, scenarios, BATTERY, checkBattery } from './live.mjs';
import { load } from './index.mjs';
import { alina, H, D } from './cast.mjs';

function fakeNode(port) {
  const now = Date.now();
  const endpoint = `http://127.0.0.1:${port}/alina`;
  // Alina from the cast; the dates are the wall clock's, because the fake is posted to live.
  const { root, host } = alina;
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
  // Every scenario in the battery file ran: the count is the file's, so it cannot go stale. (It was
  // `=== 10`, then a floor of 28 written by hand, each a number to forget when the battery changed.)
  assert.equal(out.results.length, BATTERY.scenarios.length, lines.join('\n'));
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
 * one commit and differed on day one — 27 scenarios against 26, a control in one and not the other —
 * and for a week they were held to each other by a regex over the Rust SOURCE, with a hand tokenizer
 * for its arguments. The list is now one file, js/live-scenarios.json: its order, names and expected
 * codes are data both drivers read, and each driver only builds the envelope for an id. The Rust
 * half is held by the crate's own tests (`every_scenario_in_the_battery_file_is_one_this_driver_builds`,
 * `the_battery_file_parses_and_its_one_control_is_last`), which `cargo test` runs in the gate.
 */
test('this driver runs the battery file, in its order, expecting its codes', () => {
  const list = scenarios({ targetLeaf: fakeNode(1).LEAF });
  assert.deepEqual(list.map(({ id, name, expect }) => ({ id, name, expect })), BATTERY.scenarios.map(({ id, name, expect }) => ({ id, name, expect })));
});

test('the Rust driver embeds the same battery file', () => {
  // The one thing the crate's tests cannot say about themselves: which file they read.
  const rust = readFileSync(new URL('../crates/pact/src/vectors.rs', import.meta.url), 'utf8');
  assert.ok(rust.includes('include_str!("../../../js/live-scenarios.json")'), 'crates/pact/src/vectors.rs no longer embeds js/live-scenarios.json');
});

test('an id the file names and this driver cannot build, or the reverse, stops the run', () => {
  const targetLeaf = fakeNode(1).LEAF;
  const extra = { ...BATTERY, scenarios: [{ id: 'nobody-wrote-this', name: 'x', expect: 'envelope_invalid' }, ...BATTERY.scenarios] };
  assert.throws(() => scenarios({ targetLeaf, battery: extra }), /names nobody-wrote-this, and js\/live.mjs has no builder/);
  const fewer = { ...BATTERY, scenarios: BATTERY.scenarios.filter((s) => s.id !== 'chain-empty') };
  assert.throws(() => scenarios({ targetLeaf, battery: fewer }), /builds chain-empty, which js\/live-scenarios.json does not name/);
});

test('the battery file is refused unless it has one control, last, and ids used once', () => {
  const list = BATTERY.scenarios;
  const control = list.at(-1);
  assert.throws(() => checkBattery({ ...BATTERY, scenarios: [control, ...list.slice(0, -1)] }), /control must be last/);
  assert.throws(() => checkBattery({ ...BATTERY, scenarios: [...list, { ...control, id: 'second' }] }), /exactly one scenario must be the control; 2 are/);
  assert.throws(() => checkBattery({ ...BATTERY, scenarios: [list[0], ...list] }), /is used twice/);
  assert.equal(checkBattery(BATTERY), BATTERY);
});

test('the skew scenarios are named for the window and margin they are sealed with', () => {
  const skew = String(BATTERY.window_s + BATTERY.margin_s);
  for (const id of ['past-window', 'future-window']) {
    assert.ok(BATTERY.scenarios.find((s) => s.id === id).name.includes(skew), `${id} does not name ${skew} seconds`);
  }
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
