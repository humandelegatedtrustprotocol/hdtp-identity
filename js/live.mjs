// The black-box half of the intrusion suite, aimed at a live endpoint: `node js/live.mjs --endpoint
// https://host/slug` (or `intrude.mjs --port live --endpoint …`). Mallory's artifacts are built with
// the seed library exactly as intrude.mjs builds them; what differs is the defender, which is
// whatever answers at the address, judged by the one thing a stranger can see — the answer's code.
//
// `--card <file>` supplies the card for a host that serves none at a URL (the reference node);
// `--insecure` is for a node on your own machine, whose TLS chain is its own.
//
// Only scenarios a code decides are run: the rest need the owner's state (a pin, a block, a
// tombstone) or a look inside the node, and are counted as skipped rather than pretended. One
// scenario (a contact request with a matching card) leaves a pending request behind on the
// target, because that is what it proves; aim it at a test identity.
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ed25519FromSeed, b64url, fromB64url } from '../../pact-protocol/vectors/lib/keys.mjs';
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
  const run = spawnSync(process.execPath, [fileURLToPath(new URL('../../pact-protocol/vectors/intrude.mjs', import.meta.url))], { encoding: 'utf8' });
  const m = /^(\d+) scenarios:/m.exec(run.stdout || '');
  if (!m) throw new Error('the seed suite did not report a scenario count');
  return Number(m[1]);
}

/**
 * What a stranger can read from an answer: the error's code, or `sealed` for a sealed result.
 *
 * Takes the parsed body or the raw text. A streamable-HTTP receiver may answer as an event stream
 * (`data: {…}` lines) — the reference node does — and a tool error may arrive as the JSON-RPC
 * error, as a `code` in the tool's own text, or on the result. The Rust driver
 * (`pact vectors intrude`) has read all of these since 2026-09-18; this one read two, which was
 * enough for the hosted platform and the seed's fake and for nothing else.
 */
export function answerCode(body) {
  if (typeof body === 'string') {
    const t = body.trimStart();
    const payload = t.startsWith('event:') || t.startsWith('data:')
      ? body.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trim()).join('')
      : body;
    try { body = JSON.parse(payload); } catch { return `unknown:not-json(${payload.slice(0, 60)})`; }
  }
  // A JSON-RPC `error.code` is a NUMBER, and every caller of this treats the answer as a string.
  // Returning it raw threw `code.startsWith is not a function` out of `post()`, killed the run as an
  // unhandled rejection and lost every result already collected — against any receiver that answers
  // a plain JSON-RPC error, which is what the reference node does for a tool it does not have. The
  // Rust driver has read this shape since 2026-09-18; this one never did (measured 2026-09-20).
  if (body && body.error) {
    const c = body.error.data?.code ?? body.error.code;
    return typeof c === 'string' ? c : `unknown:jsonrpc-${c ?? 'error'}`;
  }
  for (const item of body?.result?.content ?? []) {
    if (typeof item?.text !== 'string') continue;
    let r; try { r = JSON.parse(item.text); } catch { continue; }
    // All FOUR members, each a non-empty string — as the Rust driver requires. Two string members,
    // possibly empty, scored the CONTROL as passed: `{"protected":"","ct":""}` was "sealed".
    if (r && ['protected', 'enc', 'ct', 'sig'].every((k) => typeof r[k] === 'string' && r[k] !== '')) return 'sealed';
    if (r && typeof r.code === 'string') return r.code;
    if (r && r.error) return typeof r.error.code === 'string' ? r.error.code : `unknown:jsonrpc-${r.error.code ?? 'error'}`;
  }
  if (typeof body?.result?.code === 'string') return body.result.code;
  if (body?.result?.isError) return 'unknown:isError';
  return body?.result ? 'result' : 'unknown';
}

/** §13.3's skew window, and the margin a LIVE run adds to it. */
const WINDOW = 300, MARGIN = 30;

/**
 * The scenarios, in an order that matters, by an attacker nobody has met.
 *
 * Three things here were wrong until 2026-09-20, and every one of them passed against the seed's
 * fake node and failed against a real one — which nothing had been aimed at since the list grew:
 *
 *  - **Mallory is new every run.** Her keys came from a fixed seed, so she was the same person each
 *    time, and the control below leaves her request PENDING on the target: from the second run on
 *    she was no stranger anywhere this had been aimed, and "a stranger in the small form" was
 *    answered as the pending contact she had become.
 *  - **The control runs LAST.** It sat ninth of twenty-seven, so the eighteen scenarios after it
 *    were not a stranger's either; two of them (a replayed small form, a sealed tools/list) were
 *    answered with a sealed refusal — correctly — and reported as intrusions that reproduce.
 *  - **The skew scenarios carry a margin.** "301 seconds in the future" was sealed when the list
 *    was built and posted seconds later, by which time it was 299 seconds in the future and inside
 *    the window: the receiver accepted it, correctly. The exact boundary (300 in, 301 out) is the
 *    offline suite's, where there is no transit and one clock. Over a network the honest claim is
 *    "well outside the window is refused", so these are 300 + 30.
 *
 * The names are the Rust driver's too (`pact vectors intrude`), and js/live.test.mjs holds the two
 * lists to each other: they drifted apart the day they were written, 27 against 26.
 */
export function scenarios({ targetLeaf, now = Date.now() }) {
  const nowS = Math.floor(now / 1000);
  const E_M = 'https://mallory.example/mcp';
  const rootM = ed25519FromSeed(randomBytes(32)), hostM = ed25519FromSeed(randomBytes(32));
  const ROOT_M = buildRoot({ cn: 'Mallory', key: rootM, notBefore: new Date(now - D), label: 'live/root_m' });
  const LEAF_M = buildLeaf({ cn: 'Mallory', rootCn: 'Mallory', root: rootM, hostKey: hostM, endpoint: E_M, notBefore: new Date(now - H), notAfter: new Date(now + 365 * D), label: 'live/leaf_m' });
  const chainM = [LEAF_M, ROOT_M];
  const card = encodeCard({ fn: 'Mallory', cert: LEAF_M, seal: 'required' });
  let n = 0;
  const env = (o) => sealEnvelope({ senderKey: hostM, senderChain: chainM, recipientLeaf: targetLeaf, ts: nowS, msgId: `live-${++n}-${now}`, ...o });
  const message = (o = {}) => env({ params: { name: 'send_message', arguments: { msg_id: 'm', text: 'hello' } }, ...o });
  const request = (o = {}) => env({ params: { name: 'request_contact', arguments: { card, note: 'hi' } }, ...o });
  const tamper = (e) => ({ ...e, sig: b64url(Buffer.from([1, 2, 3])) });
  // `sig` covers `protected ‖ enc ‖ ct` with nothing between them, so a byte moved
  // across the enc/ct boundary leaves the signed bytes identical: what refuses it is
  // `enc` being the suite's own length (§13.1).
  const slid = (e) => { const enc = fromB64url(e.enc), ct = fromB64url(e.ct); return { ...e, enc: b64url(enc.subarray(0, enc.length - 1)), ct: b64url(Buffer.concat([enc.subarray(enc.length - 1), ct])) }; };
  // The suite the target's key does NOT take, claimed in a header the envelope is sealed under.
  const realSuite = JSON.parse(fromB64url(message().protected).toString()).suite;
  const otherSuite = realSuite === 'PACT-SEAL-X25519' ? 'PACT-SEAL-P256' : 'PACT-SEAL-X25519';
  // Certificates the receiver must refuse: a CA-signed intermediate in the root slot
  // (there is no authority above the person), and leaves outside their validity.
  const INTER_M = buildLeaf({ cn: 'Mallory', rootCn: 'Mallory', root: rootM, hostKey: rootM, endpoint: E_M, notBefore: new Date(now - D), notAfter: new Date(now + 365 * D), cA: true, usage: [5], label: 'live/inter_m' });
  const FUTURE_M = buildLeaf({ cn: 'Mallory', rootCn: 'Mallory', root: rootM, hostKey: hostM, endpoint: E_M, notBefore: new Date(now + H), notAfter: new Date(now + 300 * D), label: 'live/future_m' });
  const EXPIRED_M = buildLeaf({ cn: 'Mallory', rootCn: 'Mallory', root: rootM, hostKey: hostM, endpoint: E_M, notBefore: new Date(now - 400 * D), notAfter: new Date(now - D), label: 'live/expired_m' });
  const INVALID = 'envelope_invalid';
  return [
    { name: 'a stranger in the small form, naming a leaf nobody holds', envelope: message({ reference: true }), expect: 'chain_required' },
    { name: 'the same small-form envelope replayed', envelope: message({ reference: true }), twice: true, expect: 'chain_required' },
    { name: 'a stranger in the full form calling a contact tool', envelope: message(), expect: INVALID },
    { name: 'a full-form envelope whose signature was tampered', envelope: tamper(message()), expect: INVALID },

    // Headers no honest sealer writes, each SEALED UNDER the forged header: rewritten afterwards,
    // the AAD stops matching and the envelope is refused for that alone, whatever the header says.
    { name: 'an envelope sealed to a key this endpoint never held', envelope: message({ header: { kid: 'sha256:' + b64url(Buffer.alloc(32, 7)) } }), expect: INVALID },
    { name: 'a header carrying a member the protocol does not list', envelope: message({ header: { from: 'sha256:x' } }), expect: INVALID },
    { name: 'a suite that is not the one the recipient key takes', envelope: message({ header: { suite: otherSuite } }), expect: INVALID },

    // Chain confusion, over the wire. The offline battery proves the library
    // refuses these shapes; these prove the DEPLOYED node runs that library on
    // the path a stranger actually reaches, past its edge and its router.
    { name: 'a chain of one certificate', envelope: message({ chainInside: [LEAF_M] }), expect: INVALID },
    { name: 'an empty chain', envelope: message({ chainInside: [] }), expect: INVALID },
    { name: 'a chain of three certificates', envelope: message({ chainInside: [LEAF_M, ROOT_M, ROOT_M] }), expect: INVALID },
    { name: 'the chain in reverse order', envelope: message({ chainInside: [ROOT_M, LEAF_M] }), expect: INVALID },
    { name: 'the root presented as its own leaf', envelope: message({ chainInside: [ROOT_M, ROOT_M] }), expect: INVALID },
    { name: 'the leaf presented as its own root', envelope: message({ chainInside: [LEAF_M, LEAF_M] }), expect: INVALID },
    { name: 'an intermediate posing as the root', envelope: message({ chainInside: [LEAF_M, INTER_M] }), expect: INVALID },

    // Time, well outside the edges the receiver is supposed to hold.
    { name: 'a leaf that is not valid yet', envelope: message({ chainInside: [FUTURE_M, ROOT_M] }), expect: INVALID },
    { name: 'an expired leaf', envelope: message({ chainInside: [EXPIRED_M, ROOT_M] }), expect: INVALID },
    { name: 'an envelope an hour old', envelope: message({ ts: nowS - 3600, exp: nowS - 3540 }), expect: INVALID },
    { name: `an envelope ${WINDOW + MARGIN} seconds old`, envelope: message({ ts: nowS - WINDOW - MARGIN, exp: nowS + 300 }), expect: INVALID },
    { name: `an envelope ${WINDOW + MARGIN} seconds in the future`, envelope: message({ ts: nowS + WINDOW + MARGIN, exp: nowS + 900 }), expect: INVALID },
    { name: 'an envelope asking to be remembered for a year', envelope: message({ ts: nowS, exp: nowS + 365 * 86400 }), expect: INVALID },

    // The retired generation, refused by a node that no longer implements it.
    { name: 'a v: 1 header, the retired generation', envelope: message({ header: { v: 1 } }), expect: INVALID },
    { name: 'a header claiming a version that does not exist yet', envelope: message({ header: { v: 3 } }), expect: INVALID },
    { name: 'a header whose ts and exp are strings', envelope: message({ header: { ts: String(nowS), exp: String(nowS + 600) } }), expect: INVALID },
    { name: 'an empty msg_id', envelope: message({ msgId: '' }), expect: INVALID },
    { name: 'a result envelope dispatched as a request', envelope: message({ cty: 'application/pact-result+json' }), expect: INVALID },
    { name: 'a sealed tools/list from a stranger', envelope: env({ method: 'tools/list', params: {} }), expect: INVALID },
    { name: 'a byte moved from the encapsulated key into the ciphertext', envelope: slid(message()), expect: INVALID },

    // THE CONTROL, and it is last on purpose. Twenty-six answers of `envelope_invalid` are also
    // what a receiver that refuses EVERYTHING gives; this is the one well-formed call from a
    // stranger that must get through the same door — sealed, by the target, to her key. It
    // leaves a pending request behind, which is why nothing may come after it.
    { name: 'CONTROL: a stranger asking for contact with a card that is her leaf', envelope: request(), expect: 'sealed', note: 'leaves a contact request on the target' },
    // Every entry carries the ATTACKER's root, because "she is new every run" is otherwise
    // untestable from outside: her chain rides inside the ciphertext, and the signature over it
    // differs between two calls whatever her long-term keys are (HPKE's ephemeral is fresh each
    // time). A test written against `sig` therefore passed with the fixed seed this fix removed.
    // `endpoint` used to be spread here and nothing ever read it.
  ].map((s) => ({ ...s, attacker: b64url(ROOT_M) }));
}

/**
 * The target's card: from a file when one is given, from `<endpoint>/card.vcf` otherwise. That URL
 * is one deployment's convenience — SPEC §9 puts the card on the invite landing page, and the
 * reference node serves no card at a URL of its own — so without `card` this could be aimed at the
 * hosted platform and at nothing else.
 */
export async function fetchTargetLeaf(endpoint, fetchImpl = fetch, cardText = null) {
  if (cardText == null) {
    const res = await fetchImpl(endpoint.replace(/\/+$/, '') + '/card.vcf');
    if (!res.ok) throw new Error(`card.vcf answered ${res.status} — a host need not serve a card at a URL of its own (SPEC §9); save the target's card and pass --card <file>`);
    cardText = await res.text();
  }
  const card = decodeCard(cardText);
  if (card.error) throw new Error(`the target's card is not a 2.0 card: ${card.why}`);
  return { leaf: card.cert, root: card.root, endpoint: card.endpoint };
}

async function rpc(endpoint, message, fetchImpl, session) {
  const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
  if (session) headers['mcp-session-id'] = session;
  // A hung receiver hung the whole battery; the Rust driver has had a 20s global timeout all along.
  const res = await fetchImpl(endpoint, { method: 'POST', headers, body: JSON.stringify(message), signal: AbortSignal.timeout(20_000) });
  return { status: res.status, text: await res.text(), session: res.headers.get('mcp-session-id') };
}

/**
 * The MCP handshake, before any scenario.
 *
 * Without it a receiver that keeps sessions answers every post with the same session error, and
 * this driver then reported 27 of 27 intrusions as REPRODUCING against the reference node — each
 * one an `http_400` that had never reached the PACT layer (measured 2026-09-20). A stateless
 * receiver hands back no session id, and then this changes nothing.
 */
export async function initialize(endpoint, fetchImpl = fetch) {
  const first = await rpc(endpoint, { jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'pact-identity js/live.mjs', version: '1' } } }, fetchImpl, null);
  if (!first.session && !first.text.includes('"result"')) throw new Error(`${endpoint}: initialize was refused (HTTP ${first.status}), so no scenario could be posted: ${first.text.slice(0, 200)}`);
  if (first.session) await rpc(endpoint, { jsonrpc: '2.0', method: 'notifications/initialized' }, fetchImpl, first.session);
  return first.session;
}

export async function post(endpoint, envelope, fetchImpl = fetch, session = null) {
  const res = await rpc(endpoint, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'sealed_call', arguments: envelope } }, fetchImpl, session);
  const code = answerCode(res.text);
  return { status: res.status, code: code.startsWith('unknown:not-json') && res.status >= 400 ? `http_${res.status}` : code };
}

/** An answer that is no PACT answer at all: the scenario never reached the layer it tests. */
const unreached = (code) => code.startsWith('http_') || code.startsWith('unknown');

/**
 * `endpoint` is what gets DIALLED. It is usually the address in the target's leaf, and for a node
 * on your own machine it is not (the leaf names the public address; you dial 127.0.0.1) — so this
 * dials what it was given, as `pact vectors intrude --against` does, and seals to the card.
 */
export async function runLive({ endpoint, card = null, fetchImpl = fetch, now = Date.now(), log = console.log }) {
  const dial = endpoint.replace(/\/+$/, '');
  const target = await fetchTargetLeaf(dial, fetchImpl, card);
  log(`target: ${target.endpoint} (root ${target.root})${dial === target.endpoint ? '' : `, dialled at ${dial}`}`);
  const session = await initialize(dial, fetchImpl);
  if (session) log(`session: ${session}`);
  const results = [];
  for (const s of scenarios({ targetLeaf: target.leaf, now })) {
    const first = await post(dial, s.envelope, fetchImpl, session);
    let got = first.code;
    if (s.twice) { const second = await post(dial, s.envelope, fetchImpl, session); got = second.code === first.code ? first.code : `${first.code} then ${second.code}`; }
    // A refused CONTROL is the opposite of an intrusion: the one call that must get through was
    // blocked, which is what a receiver refusing everything does. It was scored `REPRODUCES` —
    // "something got in" — here, after the Rust driver had been given its own verdict for it.
    const verdict = got === s.expect ? 'blocked' : unreached(got) ? 'UNREACHED' : s.expect === 'sealed' ? 'CONTROL REFUSED' : 'REPRODUCES';
    results.push({ name: s.name, expect: s.expect, got, verdict });
    log(`  ${verdict.padEnd(10)} ${s.name} → ${got}${s.note ? ` (${s.note})` : ''}`);
  }
  const reproduces = results.filter((r) => r.verdict === 'REPRODUCES').length;
  const unreachedCount = results.filter((r) => r.verdict === 'UNREACHED').length;
  const controlRefused = results.filter((r) => r.verdict === 'CONTROL REFUSED').length;
  const total = seedScenarioCount();
  log(`\n${results.length} scenarios against ${target.endpoint}: ${results.length - reproduces - unreachedCount - controlRefused} blocked, ${reproduces} reproduce, ${unreachedCount} never reached a PACT answer${controlRefused ? ', and the CONTROL was refused: this receiver refuses a legitimate call too' : ''}; ${Math.max(0, total - results.length)} of the seed's ${total} were not run here`);
  return { results, reproduces, unreached: unreachedCount, controlRefused, skipped: total - results.length, seedScenarios: total };
}

const readCard = (file) => (file ? readFileSync(file, 'utf8') : null);

/** The one command-line entry, for `node js/live.mjs …` and for `intrude.mjs --port live …` alike. */
export async function cli(argv) {
  const arg = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
  const endpoint = arg('--endpoint');
  if (!endpoint) { console.error('usage: --endpoint https://host/slug [--card file.vcf] [--insecure]'); return 2; }
  const cardFile = arg('--card');
  // A node on your own machine serves TLS under its own chain, which no public authority signed.
  // With the card from a FILE, what is measured does not rest on the transport: every envelope is
  // sealed to the key in that card. WITHOUT one the card is fetched over the very channel this flag
  // stops authenticating, so whoever answers supplies the key all 28 envelopes are sealed to, and a
  // clean "28 blocked" says nothing about the target. The Rust driver was given this refusal on
  // 2026-09-20 and this one was not — the same defect, fixed in one of two copies.
  if (argv.includes('--insecure')) {
    if (!cardFile) { console.error('--insecure turns off certificate verification, so the card must come from a file: pass --card <file>'); return 2; }
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }
  const { reproduces, unreached: missed, controlRefused } = await runLive({ endpoint, card: readCard(cardFile) });
  return reproduces || missed || controlRefused ? 1 : 0;
}

// `pathToFileURL`, not `URL#pathname`: a pathname is percent-encoded and argv is not, so from a
// checkout under "my repo/" the comparison failed, the module did nothing, and node exited 0 — which
// for a security battery reads as "no intrusions reproduce".
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exit(await cli(process.argv));
