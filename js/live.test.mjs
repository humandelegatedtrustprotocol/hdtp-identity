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
  return { node, card, endpoint, LEAF };
}

test('every black-box scenario is blocked by the seed node behind an HTTP door', async () => {
  const server = createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { node, card, endpoint } = fakeNode(server.address().port);
  server.on('request', (req, res) => {
    if (req.method === 'GET' && req.url.endsWith('/card.vcf')) { res.setHeader('content-type', 'text/vcard'); res.end(card); return; }
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      node.now = Date.now();
      const rpc = JSON.parse(body);
      res.setHeader('content-type', 'application/json');
      // A stateless receiver: it answers the MCP handshake and hands back no session id, which is
      // how the hosted platform behaves. (The reference node keeps sessions; the driver's handshake
      // is proven against that one by aiming it there.)
      if (rpc.method === 'initialize') { res.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'seed', version: '1' } } })); return; }
      if (rpc.method !== 'tools/call') { res.statusCode = 202; res.end(); return; }
      const answer = receive(node, rpc.params.arguments);
      if (answer.code === 'ok') res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: JSON.stringify({ protected: 'x', enc: 'x', ct: 'x', sig: 'x' }) }] } }));
      else res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: answer.code, data: { code: answer.code, why: answer.why } } }));
    });
  });
  const lines = [];
  // The seed's card intake refuses an http endpoint only at the address guard, which the fake does not run; the adapter dials what it was given.
  const out = await runLive({ endpoint, fetchImpl: (u, init) => fetch(u.replace('https://alina.example/mcp', endpoint), init), log: (l) => lines.push(l) });
  server.close();
  assert.equal(out.reproduces, 0, lines.join('\n'));
  // A FLOOR, not a count. This was `=== 10`, and it locked a stale number in the day the live
  // battery grew to 26 (2026-09-18): the test failed from then on, and nothing ran it — its only
  // runner was a CI job that never got past its first step. What a number here is for is noticing
  // the battery SHRINK, so it may only ever be raised.
  assert.ok(out.results.length >= 28, `the live battery ran ${out.results.length} scenarios; it has run 28`);
  assert.equal(out.unreached, 0, 'every scenario reached a PACT answer');
  // The total comes from the seed, so this cannot lock a stale number in: what it asserts is that
  // the two add up.
  assert.equal(out.skipped, out.seedScenarios - out.results.length);
  assert.ok(out.seedScenarios >= out.results.length, 'the seed has at least the scenarios a live run covers');
  assert.ok(out.results.every((r) => r.verdict === 'blocked'));
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
  const mine = scenarios({ endpoint: 'https://t.example/mcp', targetLeaf: fakeNode(1).LEAF }).map((s) => s.name);
  assert.ok(names.length >= 28, `read ${names.length} scenario names out of the Rust driver; the extraction has stopped seeing it`);
  assert.deepEqual(names, mine);
});

test('the control is last, because after it the attacker is no stranger', () => {
  const list = scenarios({ endpoint: 'https://t.example/mcp', targetLeaf: fakeNode(1).LEAF });
  const controls = list.filter((s) => s.expect === 'sealed');
  assert.equal(controls.length, 1, 'exactly one scenario must get THROUGH: a receiver that refuses everything fails it');
  assert.equal(list.at(-1), controls[0]);
});

test('the attacker is new every run', () => {
  const chainOf = () => JSON.stringify(scenarios({ endpoint: 'https://t.example/mcp', targetLeaf: fakeNode(1).LEAF }).at(-1).envelope.sig);
  assert.notEqual(chainOf(), chainOf());
});
