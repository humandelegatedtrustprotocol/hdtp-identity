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
import { runLive, answerCode } from './live.mjs';

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
      const answer = receive(node, rpc.params.arguments);
      res.setHeader('content-type', 'application/json');
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
  assert.ok(out.results.length >= 27, `the live battery ran ${out.results.length} scenarios; it has run 27`);
  // The total comes from the seed, so this cannot lock a stale number in: what it asserts is that
  // the two add up.
  assert.equal(out.skipped, out.seedScenarios - out.results.length);
  assert.ok(out.seedScenarios >= out.results.length, 'the seed has at least the scenarios a live run covers');
  assert.ok(out.results.every((r) => r.verdict === 'blocked'));
});

test('answerCode reads the three shapes an endpoint answers in', () => {
  assert.equal(answerCode({ error: { code: -32000, data: { code: 'chain_required' } } }), 'chain_required');
  assert.equal(answerCode({ result: { content: [{ text: JSON.stringify({ protected: 'a', enc: 'b', ct: 'c', sig: 'd' }) }] } }), 'sealed');
  assert.equal(answerCode({ result: { content: [{ text: JSON.stringify({ error: { code: 'envelope_invalid' } }) }] } }), 'envelope_invalid');
});
