// The black-box half of the intrusion suite, aimed at a live endpoint: `node js/live.mjs --endpoint
// https://host/slug` (or `intrude.mjs --port live --endpoint …`). Mallory's artifacts are built with
// the seed library exactly as intrude.mjs builds them; what differs is the defender, which is
// whatever answers at the address, judged by the one thing a stranger can see — the answer's code.
//
// Only scenarios a code decides are run: the rest need the owner's state (a pin, a block, a
// tombstone) or a look inside the node, and are counted as skipped rather than pretended. One
// scenario (a contact request with a matching card) leaves a pending request behind on the
// target, because that is what it proves; aim it at a test identity.
import { spawnSync } from 'node:child_process';
import { seed, ed25519FromSeed, b64url } from '../../pact-protocol/vectors/lib/keys.mjs';
import { buildRoot, buildLeaf } from '../../pact-protocol/vectors/lib/x509.mjs';
import { encodeCard, decodeCard } from '../../pact-protocol/vectors/lib/card.mjs';
import { sealEnvelope } from '../../pact-protocol/vectors/lib/envelope.mjs';

const H = 3_600_000, D = 86_400_000;

/**
 * How many scenarios the seed suite has, counted from the seed itself rather than written down
 * here. A number in this file was a number to go stale: it said 79 while the seed had 81, so a live
 * run understated what it had not tested. The seed prints one line per scenario, and that is the
 * count.
 */
export function seedScenarioCount() {
  const run = spawnSync(process.execPath, [new URL('../../pact-protocol/vectors/intrude.mjs', import.meta.url).pathname], { encoding: 'utf8' });
  const m = /^(\d+) scenarios:/m.exec(run.stdout || '');
  if (!m) throw new Error('the seed suite did not report a scenario count');
  return Number(m[1]);
}

/** What a stranger can read from an answer: the error's code, or `sealed` for a sealed result. */
export function answerCode(body) {
  if (body && body.error) return body.error.data?.code ?? body.error.code ?? 'error';
  const text = body?.result?.content?.[0]?.text;
  if (typeof text === 'string') {
    try { const r = JSON.parse(text); if (r && typeof r.protected === 'string' && typeof r.ct === 'string') return 'sealed'; if (r && r.error) return r.error.code ?? 'error'; } catch { /* not JSON */ }
  }
  if (body?.result?.isError) return 'error';
  return body?.result ? 'result' : 'unknown';
}

export function scenarios({ endpoint, targetLeaf, now = Date.now() }) {
  const nowS = Math.floor(now / 1000);
  const E_M = 'https://mallory.example/mcp';
  const rootM = ed25519FromSeed(seed('live/root/mallory')), hostM = ed25519FromSeed(seed('live/host/mallory'));
  const ROOT_M = buildRoot({ cn: 'Mallory', key: rootM, notBefore: new Date(now - D), label: 'live/root_m' });
  const LEAF_M = buildLeaf({ cn: 'Mallory', rootCn: 'Mallory', root: rootM, hostKey: hostM, endpoint: E_M, notBefore: new Date(now - H), notAfter: new Date(now + 365 * D), label: 'live/leaf_m' });
  const chainM = [LEAF_M, ROOT_M];
  const card = encodeCard({ fn: 'Mallory', cert: LEAF_M, seal: 'required' });
  let n = 0;
  const env = (o) => sealEnvelope({ senderKey: hostM, senderChain: chainM, recipientLeaf: targetLeaf, ts: nowS, msgId: `live-${++n}-${now}`, ...o });
  const message = (o = {}) => env({ params: { name: 'send_message', arguments: { msg_id: 'm', text: 'hello' } }, ...o });
  const request = (o = {}) => env({ params: { name: 'request_contact', arguments: { card, note: 'hi' } }, ...o });
  const tamper = (e) => ({ ...e, sig: b64url(Buffer.from([1, 2, 3])) });
  const replayed = message({ reference: true });
  return [
    { name: 'a stranger in the small form, naming a leaf nobody holds', envelope: message({ reference: true }), expect: 'chain_required' },
    { name: 'a stranger in the full form calling a contact tool', envelope: message(), expect: 'envelope_invalid' },
    { name: 'a full-form envelope whose signature was tampered', envelope: tamper(message()), expect: 'envelope_invalid' },
    { name: 'an envelope sealed to a key this endpoint never held', envelope: message({ header: { kid: 'sha256:' + b64url(Buffer.alloc(32, 7)) } }), expect: 'envelope_invalid' },
    { name: 'a header carrying a member the protocol does not list', envelope: message({ header: { from: 'sha256:x' } }), expect: 'envelope_invalid' },
    { name: 'an envelope an hour old', envelope: message({ ts: nowS - 3600, exp: nowS - 3540 }), expect: 'envelope_invalid' },
    { name: 'a chain of three', envelope: message({ chainInside: [LEAF_M, ROOT_M, ROOT_M] }), expect: 'envelope_invalid' },
    { name: 'a leaf presented as the root', envelope: message({ chainInside: [LEAF_M, LEAF_M] }), expect: 'envelope_invalid' },
    { name: 'a stranger asking for contact with a card that is her leaf', envelope: request(), expect: 'sealed', note: 'leaves a contact request on the target' },
    { name: 'the same small-form envelope replayed', envelope: replayed, twice: true, expect: 'chain_required' },
  ].map((s) => ({ ...s, endpoint }));
}

export async function fetchTargetLeaf(endpoint, fetchImpl = fetch) {
  const res = await fetchImpl(endpoint.replace(/\/+$/, '') + '/card.vcf');
  if (!res.ok) throw new Error(`card.vcf answered ${res.status}`);
  const card = decodeCard(await res.text());
  if (card.error) throw new Error(`the target's card is not a 2.0 card: ${card.why}`);
  return { leaf: card.cert, root: card.root, endpoint: card.endpoint };
}

export async function post(endpoint, envelope, fetchImpl = fetch) {
  const res = await fetchImpl(endpoint, {
    method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'sealed_call', arguments: envelope } }),
  });
  let body; try { body = await res.json(); } catch { body = { error: { code: `http_${res.status}` } }; }
  return { status: res.status, body, code: answerCode(body) };
}

export async function runLive({ endpoint, fetchImpl = fetch, now = Date.now(), log = console.log }) {
  const target = await fetchTargetLeaf(endpoint, fetchImpl);
  log(`target: ${target.endpoint} (root ${target.root})`);
  const results = [];
  for (const s of scenarios({ endpoint: target.endpoint, targetLeaf: target.leaf, now })) {
    const first = await post(target.endpoint, s.envelope, fetchImpl);
    let got = first.code;
    if (s.twice) { const second = await post(target.endpoint, s.envelope, fetchImpl); got = second.code === first.code ? first.code : `${first.code} then ${second.code}`; }
    const verdict = got === s.expect ? 'blocked' : 'REPRODUCES';
    results.push({ name: s.name, expect: s.expect, got, verdict });
    log(`  ${verdict.padEnd(10)} ${s.name} → ${got}${s.note ? ` (${s.note})` : ''}`);
  }
  const reproduces = results.filter((r) => r.verdict === 'REPRODUCES').length;
  const total = seedScenarioCount();
  log(`\n${results.length} scenarios against ${target.endpoint}: ${results.length - reproduces} blocked, ${reproduces} reproduce; ${total - results.length} of the seed's ${total} need the owner's state and were not run`);
  return { results, reproduces, skipped: total - results.length, seedScenarios: total };
}

if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) {
  const i = process.argv.indexOf('--endpoint');
  const endpoint = i >= 0 ? process.argv[i + 1] : null;
  if (!endpoint) { console.error('usage: node js/live.mjs --endpoint https://host/slug'); process.exit(2); }
  const { reproduces } = await runLive({ endpoint });
  process.exit(reproduces ? 1 : 0);
}
