// Both ports, the same arguments, the same answers — as a gate, not a courtesy.
//
// The vectors prove that what the ports produce agrees on the bytes a peer sees. They say nothing
// about what a port answers when a caller gets it wrong, and nothing about the members of an answer
// the vectors do not carry. That is where every cross-port defect has been found:
//
//   2026-09-15, internal: `valid_days: 0` was an error in one port and a year in the other;
//     `assemble_leaf` called a mismatched algorithm two different things; `wallet_issue` answered
//     three different shapes; the root-key refusal was worded two ways.
//   2026-09-15, ultra: the Go address guard compared an authority carrying a port against a bare
//     host, so `https://127.0.0.1:8443/mcp` passed where the Rust core refused it; and Go's
//     base64url decoder skipped illegal characters instead of failing, so a malformed `root_spkis`
//     read as "no roots to refuse against" and §9's root-key refusal failed open.
//
// Both of those were reachable from the boundary with one hostile argument, and neither test suite
// could see them: each port's tests only ever ask its own port. This file asks both.
//
//   node js/parity.mjs [--only <text>] [--verbose] [--manifest <file>]
//
// It exits non-zero on any disagreement, on an answer off the contract, and when the contract's
// surface grows without a case, so the harness cannot fall silently behind the thing it guards.
//
// It holds both ports to `contract/contract.json`, which is where the surface is WRITTEN DOWN: every
// answer of every case, from each port, is validated against the schema the contract declares for it.
// Two ports agreeing proves they are the same; it does not prove they are what the contract says, and
// a member both ports grew, or both dropped, is invisible to a comparison.
//
// The cases live in js/cases/<section>.mjs, one file per section of the contract (js/cases/index.mjs
// collects them); this file only runs them.
import { readFileSync } from 'node:fs';
import { makePort } from './port.mjs';
import { loadContract, judge } from '../contract/contract.mjs';
import { fixtures } from './cases/fixtures.mjs';
import { collect } from './cases/index.mjs';
import { rustDispatch, goDispatch } from './surface.mjs';
import { recorder } from './results.mjs';

const wasm = await makePort('wasm');
const go = await makePort('go');
if (!go) {
  console.log('the Go adapter is not built (go/bin/pact-identity-go): run `make build` in go/');
  process.exit(2);
}
const contract = await loadContract();
const { cases, expected, problems } = await collect(fixtures({ wasm, go }), contract);

// ── comparison ─────────────────────────────────────────────────────────────────────────────────
// Members are compared by name, not by the order a language's encoder happens to emit them in (Go
// sorts a map's keys; serde keeps insertion order). Order is not part of the contract.
const canonical = (v) => {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])]));
  return v;
};
const pick = (o, how, port) =>
  canonical(how === '*' ? o : typeof how === 'function' ? how(o, port) : Object.fromEntries(how.map((k) => [k, o?.[k]])));
const answer = (port, fn, args) => {
  try { return port.call(fn, args); } catch (e) { return { threw: String(e.message || e) }; }
};

const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : null;
let bad = 0;
let ran = 0;
let held = 0; // answers validated against the contract's schemas, both ports counted
let offContract = 0;
const seenCodes = new Map(); // function -> the error codes it was seen to fail with
// Which functions were compared whole on an answer that SUCCEEDED. A refusal compared whole proves
// only that both ports refuse alike; it says nothing about the members of the answer a caller
// actually uses, and that is where `card_decode` lost its entire `leaf`.
//
// "Succeeded" has to be asked of the ANSWER's own shape, not of a top-level `error`. This tested
// `!raw.error`, and two functions never put their refusal there: `decide` answers
// `{result:{code:"envelope_invalid"}, effects:[]}` and `csr_check` answers `{ok:false, why}`. So
// both were recorded as proven whole on a success while every one of their cases was a refusal —
// and the richest answers in the contract (`decide`'s tier/root/endpoint/method/form/params/leaf
// /effects, `csr_check`'s cn/spki/fingerprint/alg/endpoint/dns_name) were guarded by nothing. That
// is how `decide`'s `tool` member came to be absent in Go and `null` in Rust with the gate green.
const succeeded = (raw) =>
  raw && !raw.error && !raw.threw && raw.ok !== false && !(raw.result && raw.result.code && raw.result.code !== 'ok');
const provenWhole = new Set();
const results = recorder('parity');

for (const { id, fn, args, how } of cases) {
  if (only && !id.includes(only) && fn !== only) continue;
  ran++;
  const t0 = performance.now();
  const raw = answer(wasm, fn, args);
  const rawGo = answer(go, fn, args);
  const ms = performance.now() - t0; // the two ports' answers
  const reasons = [];
  if ((how === '*' || typeof how === 'function') && succeeded(raw)) provenWhole.add(fn);
  for (const [port, got] of [['wasm', raw], ['go', rawGo]]) {
    if (got?.threw) continue; // a port that threw has already failed the comparison below
    held++;
    const wrong = judge(contract, fn, args, got, seenCodes);
    if (wrong.length) {
      offContract++;
      reasons.push(`off the contract (${port}): ${wrong[0]}`);
      console.log(`  OFF THE CONTRACT  ${id}  (${port})`);
      for (const w of wrong.slice(0, 4)) console.log(`    ${w}`);
    }
  }
  // A case that carries the spec's answer is held to it, and counts once however many ports miss it.
  const want = expected.get(id)?.want;
  // `decide` answers under `result`; a refusal is the answer itself.
  const judged = (got) => got?.result ?? got;
  const missed = want ? [['wasm', raw], ['go', rawGo]].filter(([, got]) => Object.entries(want).some(([k, v]) => judged(got)?.[k] !== v)) : [];
  for (const [port, got] of missed) console.log(`  NOT AS THE SPEC SAYS  ${id}  (${port}): want ${JSON.stringify(want)}, got ${JSON.stringify(judged(got))}`);
  if (missed.length) {
    bad++;
    results.add(id, 'FAIL', { reason: [`not as the spec says (${missed.map(([p]) => p).join(', ')})`, ...reasons].join('; '), ms });
    continue;
  }
  const a = pick(raw, how, wasm);
  const b = pick(rawGo, how, go);
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    bad++;
    reasons.push('the ports differ');
    console.log(`  DIFFER  ${id}`);
    console.log(`    wasm ${JSON.stringify(a)}`);
    console.log(`    go   ${JSON.stringify(b)}`);
  } else if (process.argv.includes('--verbose')) {
    console.log(`  agree   ${id}`);
  }
  results.add(id, reasons.length ? 'FAIL' : 'PASS', { reason: reasons.join('; ') || null, ms });
}

// ── the coverage gate ──────────────────────────────────────────────────────────────────────────
//
// A harness that guards a surface has to know when the surface grows, and has to be reading the
// surface rather than a guess at it. Both dispatchers are read (js/surface.mjs, by structure), and
// three things are asserted:
//
//   1. the two ports and the CONTRACT FILE name the same functions — three sets, not two. `version`
//      lived in one dispatcher and not the other until this check was written; and a function in
//      `contract/contract.json` that neither port dispatches would otherwise be prose nothing runs;
//   2. every name has a case;
//   3. every name has at least one case compared whole (`'*'`), not through a key list. That is the
//      one that matters: `card_decode` dropped its entire `leaf` member in one port, and no key list
//      would have noticed, because a key list only ever looks at the keys someone thought to name.
//
// 1, and the collection's own problems (an id used twice, a case filed under the wrong section, an
// expectation for an id no case has), fail a filtered run too; 2 and 3 cannot be judged on one.
const source = (f) => readFileSync(new URL(f, import.meta.url), 'utf8');
const surfaceOf = (read, f) => { try { return read(source(f)); } catch (e) { problems.push(`${f}: ${e.message}`); return new Set(); } };
const rustNames = surfaceOf(rustDispatch, '../crates/pact-identity/src/api.rs');
const goNames = surfaceOf(goDispatch, '../go/api.go');
const contractNames = new Set(Object.keys(contract.methods));

const onlyRust = [...rustNames].filter((n) => !goNames.has(n)).sort();
const onlyGo = [...goNames].filter((n) => !rustNames.has(n)).sort();
if (onlyRust.length) problems.push(`only the Rust core dispatches: ${onlyRust.join(', ')}`);
if (onlyGo.length) problems.push(`only the Go port dispatches: ${onlyGo.join(', ')}`);
const undispatched = [...contractNames].filter((n) => !rustNames.has(n) && !goNames.has(n)).sort();
const undeclared = [...new Set([...rustNames, ...goNames])].filter((n) => !contractNames.has(n)).sort();
if (undispatched.length) problems.push(`in contract/contract.json and in neither port: ${undispatched.join(', ')}`);
if (undeclared.length) problems.push(`dispatched and not in contract/contract.json: ${undeclared.join(', ')}`);

const surface = new Set([...rustNames, ...goNames]);
surface.delete('version'); // the build, not a rule: its answer describes the port and cannot agree
const covered = new Set(cases.map(({ fn }) => fn));
const whole = provenWhole;
const coverage = [];
const uncovered = [...surface].filter((f) => !covered.has(f)).sort();
const partial = [...surface].filter((f) => covered.has(f) && !whole.has(f)).sort();
if (uncovered.length) coverage.push(`no parity case at all: ${uncovered.join(', ')}`);
if (partial.length) coverage.push(`never compared whole on an answer that succeeded, so a dropped member would not show: ${partial.join(', ')}`);

// A declared error code no case ever produced is not a failure — some are unreachable from any
// argument, and `ErrorCode` declares `key` and `internal` so a caller's switch has a name for them
// — but it is the honest measure of how much of the failure side these cases reach, so it is
// printed rather than left as an impression.
const declared = [...contractNames].flatMap((fn) => contract.methods[fn].errors.map((c) => `${fn}/${c}`));
const unseen = declared.filter((k) => {
  const [fn, code] = k.split('/');
  return !seenCodes.get(fn)?.has(code);
});

const failing = only ? problems : [...problems, ...coverage];
if (failing.length) {
  console.log('\n  THE GATE IS NOT SATISFIED');
  for (const p of failing) console.log(`    ${p}`);
}
if (only) console.log('\n  a filtered run: the coverage gate (every function has a case, one compared whole) was not evaluated');
// The gate's own two verdicts, as cases of the result file, so a run of record carries them.
results.add('the collection, and the dispatchers against the contract', problems.length ? 'FAIL' : 'PASS', { reason: problems.join('; ') || null, ms: 0 });
results.add('the coverage gate', only ? 'SKIPPED' : coverage.length ? 'FAIL' : 'PASS', { reason: only ? 'a filtered run' : coverage.join('; ') || null, ms: 0 });
results.write();

// ── the manifest ───────────────────────────────────────────────────────────────────────────────
//
// `--manifest <path>` writes what was just compared, so the record of these checks is generated
// from the run rather than transcribed from it. It is written ONLY when every case agreed and the
// gate is satisfied, on an unfiltered run, so a manifest describes checks that actually held: a file
// claiming 270 passing cases cannot be produced by a run in which they did not.
const manifestAt = process.argv[process.argv.indexOf('--manifest') + 1];
const agreed = bad === 0 && offContract === 0 && failing.length === 0;
if (process.argv.includes('--manifest') && manifestAt && !only && agreed) {
  const byFn = new Map();
  for (const { id, fn } of cases) {
    if (!byFn.has(fn)) byFn.set(fn, []);
    byFn.get(fn).push(id);
  }
  const { writeFileSync } = await import('node:fs');
  writeFileSync(manifestAt, JSON.stringify({
    generated_by: 'js/parity.mjs --manifest',
    cases: cases.length,
    functions: surface.size,
    compared_whole: [...surface].filter((f) => whole.has(f)).length,
    disagreements: bad,
    contract: {
      file: 'contract/contract.json',
      spec: contract.spec,
      methods: contractNames.size,
      answers_validated: held,
      off_contract: offContract,
      declared_error_codes: declared.length,
      codes_never_produced: unseen,
    },
    by_function: [...byFn.entries()].sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([fn, ids]) => ({ fn, in_surface: surface.has(fn), compared_whole: whole.has(fn), cases: ids })),
  }, null, 2) + '\n');
}

const total = only ? ran : cases.length;
const wholeInSurface = [...surface].filter((f) => whole.has(f)).length;
console.log(`\n${total - bad}/${total} boundary answers agree between the ports${only ? ` (filtered by ${JSON.stringify(only)})` : `; ${surface.size} functions guarded, ${wholeInSurface} of them compared whole`}`);
console.log(`${held - offContract}/${held} answers hold to contract/contract.json (spec ${contract.spec}, ${contractNames.size} functions, both ports); ${declared.length - unseen.length}/${declared.length} declared error codes were produced`);
// `bad` is a COUNT, and process.exit truncates mod 256: with 276 cases, exactly 256 disagreements
// would have exited 0.
process.exit(bad > 0 || offContract > 0 || failing.length ? 1 : 0);
