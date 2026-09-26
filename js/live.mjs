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
import { load } from './index.mjs';

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
/** The JSON-RPC body of an answer given as text: plain JSON, or an event stream's `data:` lines. */
function rpcBody(text) {
  const t = text.trimStart();
  const payload = t.startsWith('event:') || t.startsWith('data:')
    ? text.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trim()).join('')
    : text;
  try { return { body: JSON.parse(payload) }; } catch { return { start: payload.slice(0, 60) }; }
}

const looksSealed = (r) => !!r && ['protected', 'enc', 'ct', 'sig'].every((k) => typeof r[k] === 'string' && r[k] !== '');

/** The envelope a tool answered with, if it answered with something shaped like one. */
export function answeredEnvelope(body) {
  if (typeof body === 'string') body = rpcBody(body).body;
  for (const item of body?.result?.content ?? []) {
    if (typeof item?.text !== 'string') continue;
    let r; try { r = JSON.parse(item.text); } catch { continue; }
    if (looksSealed(r)) return r;
  }
  return null;
}

/**
 * What the CONTROL has to show. `answerCode` says `sealed` for anything SHAPED like an envelope —
 * four non-empty strings — which is the right price for every other scenario, where a false
 * "sealed" costs nothing. For the one call that must get THROUGH it is no evidence at all: a
 * receiver, or a carrier in front of it, answering `{"protected":"a","enc":"b","ct":"c","sig":"d"}`
 * scored the control as passed, while this driver held the key that would have said otherwise.
 *
 * So the control OPENS what it is answered with, as any caller would (§13.2), through the pinned
 * core: sealed to Mallory's leaf key, a result, for THIS call, inside the window, signed by a leaf
 * that chains to the target's root at the target's address — and carrying a result, not a sealed
 * refusal. Returns null when it does, and why not otherwise. The Rust driver does the same
 * (`control_opened`), and js/live.test.mjs holds the two to each other.
 */
export async function controlOpened(answer, { pkcs8, msgId, now, root, endpoint }) {
  const envelope = answeredEnvelope(answer);
  if (!envelope) return 'the answer carries no envelope';
  const core = await load();
  const at = new Date(Math.floor(now / 1000) * 1000).toISOString().replace('.000Z', 'Z');
  const opened = core.call('open_result', { envelope, my_pkcs8: pkcs8, msg_id: msgId, now: at, pins: [], expected_root: root, expected_endpoint: endpoint });
  // A failure of the boundary is `{ error: <code>, why }`; an envelope that OPENS is `{ ok: true, … }`
  // carrying `result` — or `error`, when what was sealed inside is a refusal.
  if (opened.ok !== true) return `${opened.error}: ${opened.why}`;
  if ('error' in opened) return `it opens, and what is inside is a refusal: ${JSON.stringify(opened.error)}`;
  return 'result' in opened ? null : 'it opens, and carries no result';
}

export function answerCode(body) {
  if (typeof body === 'string') {
    const read = rpcBody(body);
    if (!read.body) return `unknown:not-json(${read.start})`;
    body = read.body;
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
    if (looksSealed(r)) return 'sealed';
    if (r && typeof r.code === 'string') return r.code;
    if (r && r.error) return typeof r.error.code === 'string' ? r.error.code : `unknown:jsonrpc-${r.error.code ?? 'error'}`;
  }
  if (typeof body?.result?.code === 'string') return body.result.code;
  if (body?.result?.isError) return 'unknown:isError';
  return body?.result ? 'result' : 'unknown';
}

/**
 * The battery as data: js/live-scenarios.json names every scenario, its order, the code it must be
 * answered with, which one is the CONTROL and the skew window. This driver and the Rust one
 * (`pact vectors intrude`, which reads the same file through `include_str!`) only BUILD the envelope
 * for an id; js/live.test.mjs and the crate's tests hold both to the file.
 */
export const BATTERY = checkBattery(JSON.parse(readFileSync(new URL('./live-scenarios.json', import.meta.url), 'utf8')));

/**
 * What the file must be for a run to mean anything: ids that are unique, codes that are strings, and
 * exactly one CONTROL, last — after it the attacker is pending on the target and no stranger.
 */
export function checkBattery(b) {
  const list = b?.scenarios;
  if (!Array.isArray(list) || !list.length) throw new Error('js/live-scenarios.json: no scenarios');
  if (!Number.isInteger(b.window_s) || !Number.isInteger(b.margin_s)) throw new Error('js/live-scenarios.json: window_s and margin_s must be whole seconds');
  const ids = new Set();
  for (const s of list) {
    if (typeof s.id !== 'string' || typeof s.name !== 'string' || typeof s.expect !== 'string') throw new Error(`js/live-scenarios.json: every scenario has a string id, name and expect: ${JSON.stringify(s)}`);
    if (ids.has(s.id)) throw new Error(`js/live-scenarios.json: the id ${s.id} is used twice`);
    ids.add(s.id);
  }
  const controls = list.filter((s) => s.control);
  if (controls.length !== 1) throw new Error(`js/live-scenarios.json: exactly one scenario must be the control; ${controls.length} are`);
  if (list.at(-1) !== controls[0]) throw new Error('js/live-scenarios.json: the control must be last, because after it the attacker is no stranger');
  return b;
}

/**
 * The scenarios, in the file's order, by an attacker nobody has met.
 *
 * Three things here were wrong until 2026-09-20, and every one of them passed against the seed's
 * fake node and failed against a real one — which nothing had been aimed at since the list grew:
 *
 *  - **Mallory is new every run.** Her keys came from a fixed seed, so she was the same person each
 *    time, and the control leaves her request PENDING on the target: from the second run on she was
 *    no stranger anywhere this had been aimed, and "a stranger in the small form" was answered as the
 *    pending contact she had become.
 *  - **The control runs LAST.** It sat ninth, so the scenarios after it were not a stranger's either;
 *    two of them (a replayed small form, a sealed tools/list) were answered with a sealed refusal —
 *    correctly — and reported as intrusions that reproduce. The file's order is checked on load.
 *  - **The skew scenarios carry a margin.** "301 seconds in the future" was sealed when the list
 *    was built and posted seconds later, by which time it was 299 seconds in the future and inside
 *    the window: the receiver accepted it, correctly. The exact boundary (300 in, 301 out) is the
 *    offline suite's, where there is no transit and one clock. Over a network the honest claim is
 *    "well outside the window is refused", so these are `window_s + margin_s`.
 */
export function scenarios({ targetLeaf, now = Date.now(), battery = BATTERY }) {
  const nowS = Math.floor(now / 1000);
  const skew = battery.window_s + battery.margin_s;
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

  // One builder per id in the file. Headers no honest sealer writes are each SEALED UNDER the forged
  // header: rewritten afterwards, the AAD stops matching and the envelope is refused for that alone,
  // whatever the header says.
  const build = {
    'small-form-stranger': () => message({ reference: true }),
    'small-form-replayed': () => message({ reference: true }),
    'full-form-contact-tool': () => message(),
    'tampered-signature': () => tamper(message()),
    'unknown-kid': () => message({ header: { kid: 'sha256:' + b64url(Buffer.alloc(32, 7)) } }),
    'unlisted-header-member': () => message({ header: { from: 'sha256:x' } }),
    'wrong-suite': () => message({ header: { suite: otherSuite } }),
    // Chain confusion, over the wire. The offline battery proves the library refuses these shapes;
    // these prove the DEPLOYED node runs that library on the path a stranger actually reaches.
    'chain-of-one': () => message({ chainInside: [LEAF_M] }),
    'chain-empty': () => message({ chainInside: [] }),
    'chain-of-three': () => message({ chainInside: [LEAF_M, ROOT_M, ROOT_M] }),
    'chain-reversed': () => message({ chainInside: [ROOT_M, LEAF_M] }),
    'root-as-leaf': () => message({ chainInside: [ROOT_M, ROOT_M] }),
    'leaf-as-root': () => message({ chainInside: [LEAF_M, LEAF_M] }),
    'intermediate-as-root': () => message({ chainInside: [LEAF_M, INTER_M] }),
    // Time, well outside the edges the receiver is supposed to hold.
    'leaf-not-yet-valid': () => message({ chainInside: [FUTURE_M, ROOT_M] }),
    'leaf-expired': () => message({ chainInside: [EXPIRED_M, ROOT_M] }),
    'hour-old': () => message({ ts: nowS - 3600, exp: nowS - 3540 }),
    'past-window': () => message({ ts: nowS - skew, exp: nowS + 300 }),
    'future-window': () => message({ ts: nowS + skew, exp: nowS + 900 }),
    'year-lifetime': () => message({ ts: nowS, exp: nowS + 365 * 86400 }),
    // The retired generation, refused by a node that no longer implements it.
    'retired-v1': () => message({ header: { v: 1 } }),
    'future-v3': () => message({ header: { v: 3 } }),
    'string-times': () => message({ header: { ts: String(nowS), exp: String(nowS + 600) } }),
    'empty-msg-id': () => message({ msgId: '' }),
    'result-as-request': () => message({ cty: 'application/pact-result+json' }),
    'stranger-tools-list': () => env({ method: 'tools/list', params: {} }),
    'enc-byte-slid': () => slid(message()),
    // THE CONTROL: the one well-formed call from a stranger that must get through the same door —
    // sealed, by the target, to her key. Every other answer of the battery is also what a receiver
    // that refuses EVERYTHING gives.
    control: () => request(),
  };
  const named = new Set(battery.scenarios.map((s) => s.id));
  const unnamed = Object.keys(build).filter((id) => !named.has(id));
  if (unnamed.length) throw new Error(`js/live.mjs builds ${unnamed.join(', ')}, which js/live-scenarios.json does not name`);
  return battery.scenarios.map((s) => {
    if (!build[s.id]) throw new Error(`js/live-scenarios.json names ${s.id}, and js/live.mjs has no builder for it`);
    const envelope = build[s.id]();
    const control = s.control
      ? { pkcs8: b64url(hostM.priv.export({ format: 'der', type: 'pkcs8' })), msgId: JSON.parse(fromB64url(envelope.protected).toString()).msg_id }
      : undefined;
    // Every entry carries the ATTACKER's root, because "she is new every run" is otherwise
    // untestable from outside: her chain rides inside the ciphertext, and the signature over it
    // differs between two calls whatever her long-term keys are (HPKE's ephemeral is fresh each
    // time). A test written against `sig` therefore passed with the fixed seed this fix removed.
    return { ...s, envelope, ...(control ? { control } : {}), attacker: b64url(ROOT_M) };
  });
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
  return { status: res.status, text: res.text, code: code.startsWith('unknown:not-json') && res.status >= 400 ? `http_${res.status}` : code };
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
    let verdict = got === s.expect ? 'blocked' : unreached(got) ? 'UNREACHED' : s.expect === 'sealed' ? 'CONTROL REFUSED' : 'REPRODUCES';
    // …and an answer that LOOKS sealed is opened, with the key this driver has held all along. Only
    // the expected `sealed` is worth opening: a refusal and an unreached run have said what they are.
    let unopened = null;
    if (s.control && verdict === 'blocked') {
      unopened = await controlOpened(first.text, { ...s.control, now, root: target.root, endpoint: target.endpoint });
      if (unopened) verdict = 'CONTROL UNOPENED';
    }
    results.push({ name: s.name, expect: s.expect, got, verdict, ...(unopened ? { unopened } : {}) });
    log(`  ${verdict.padEnd(10)} ${s.name} → ${got}${s.note ? ` (${s.note})` : ''}`);
    if (unopened) log(`  ${''.padEnd(10)} …and what it was answered with does not open: ${unopened}`);
  }
  const reproduces = results.filter((r) => r.verdict === 'REPRODUCES').length;
  const unreachedCount = results.filter((r) => r.verdict === 'UNREACHED').length;
  const controlRefused = results.filter((r) => r.verdict === 'CONTROL REFUSED').length;
  const controlUnopened = results.filter((r) => r.verdict === 'CONTROL UNOPENED').length;
  const total = seedScenarioCount();
  log(`\n${results.length} scenarios against ${target.endpoint}: ${results.length - reproduces - unreachedCount - controlRefused - controlUnopened} blocked, ${reproduces} reproduce, ${unreachedCount} never reached a PACT answer${controlRefused ? ', and the CONTROL was refused: this receiver refuses a legitimate call too' : ''}${controlUnopened ? ", and the CONTROL's answer looked sealed and did not open: nothing here shows a call can get through" : ''}; ${Math.max(0, total - results.length)} of the seed's ${total} were not run here`);
  return { results, reproduces, unreached: unreachedCount, controlRefused, controlUnopened, skipped: total - results.length, seedScenarios: total };
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
  // stops authenticating, so whoever answers supplies the key every envelope is sealed to, and a
  // clean "all blocked" says nothing about the target. The Rust driver was given this refusal on
  // 2026-09-20 and this one was not — the same defect, fixed in one of two copies.
  if (argv.includes('--insecure')) {
    if (!cardFile) { console.error('--insecure turns off certificate verification, so the card must come from a file: pass --card <file>'); return 2; }
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }
  const { reproduces, unreached: missed, controlRefused, controlUnopened } = await runLive({ endpoint, card: readCard(cardFile) });
  return reproduces || missed || controlRefused || controlUnopened ? 1 : 0;
}

// `pathToFileURL`, not `URL#pathname`: a pathname is percent-encoded and argv is not, so from a
// checkout under "my repo/" the comparison failed, the module did nothing, and node exited 0 — which
// for a security battery reads as "no intrusions reproduce".
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exit(await cli(process.argv));
