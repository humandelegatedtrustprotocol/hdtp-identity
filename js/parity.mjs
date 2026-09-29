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
// surface grows without a case, so the harness cannot fall silently behind the thing it guards. The
// one exception is a case js/cases/known-divergences.json excuses, and only while it fails exactly as
// that entry says (js/cases/known.mjs): the divergences the generated cases found on the day they
// were written, before any was fixed, each waiting on the audit finding it names.
//
// It holds both ports to `contract/contract.json`, which is where the surface is WRITTEN DOWN: every
// answer of every case, from each port, is validated against the schema the contract declares for it.
// Two ports agreeing proves they are the same; it does not prove they are what the contract says, and
// a member both ports grew, or both dropped, is invisible to a comparison.
//
// The cases live in js/cases/<section>.mjs, one file per section of the contract (js/cases/index.mjs
// collects them), and in js/cases/generated.mjs, which makes the shapes of a caller's mistake for
// every function from the contract itself; this file only runs them.
import { readFileSync } from 'node:fs';
import { makePort, RawArgs } from './port.mjs';
import { loadContract, judge } from '../contract/contract.mjs';
import { fixtures } from './cases/fixtures.mjs';
import { collect } from './cases/index.mjs';
import { pickBases, generate } from './cases/generated.mjs';
import { readKnown, verdict } from './cases/known.mjs';
import { rustDispatch, goDispatch } from './surface.mjs';
import { recorder } from './results.mjs';

const wasm = await makePort('wasm');
const go = await makePort('go');
if (!go) {
  console.log('the Go adapter is not built (go/bin/pact-identity-go): run `make build` in go/');
  process.exit(2);
}
const contract = await loadContract();
const f = fixtures({ wasm, go });
const { cases: written, expected, problems } = await collect(f, contract);

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
// Each case is asked of the two ports once, whatever asks first: the generated cases' bases are asked
// before the run, filtered or not, and the run takes their answers from here.
const asked = new Map();
const ask = (c) => {
  if (!asked.has(c)) asked.set(c, [answer(wasm, c.fn, c.args), answer(go, c.fn, c.args)]);
  return asked.get(c);
};

const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : null;
let bad = 0;
let ran = 0;
let held = 0; // answers validated against the contract's schemas, both ports counted
let offContract = 0; // of those, the answers off the contract, excused or not
let offExcused = 0; // …and of THOSE, the answers of a known divergence
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
const verbose = process.argv.includes('--verbose');

// ── the generated cases ─────────────────────────────────────────────────────────────────────────
// js/cases/generated.mjs: every function's shapes of a caller's mistake, from the contract, varied
// from one hand-written case that succeeds on both ports (its base). They join the hand-written ones.
const picked = pickBases(contract, written, ask, succeeded);
problems.push(...picked.problems);
const made = generate(contract, picked.bases, f.outside);
const handIds = new Set(written.map(({ id }) => id));
for (const { id } of made.cases) if (handIds.has(id)) problems.push(`the case id ${JSON.stringify(id)} is both written and generated`);
for (const [id, want] of made.expected) expected.set(id, { want, file: 'generated' });
const cases = [...written, ...made.cases];

// ── the known divergences ───────────────────────────────────────────────────────────────────────
// js/cases/known-divergences.json (js/cases/known.mjs says how it is read): the cases that fail today,
// each with the finding that will close it. A case that fails exactly as its entry says is excused;
// any other failure, an entry for a case that passes, and an entry for a case nobody has, fail the run.
const known = readKnown(JSON.parse(readFileSync(new URL('./cases/known-divergences.json', import.meta.url), 'utf8')));
problems.push(...known.problems);
const allIds = new Set(cases.map(({ id }) => id));
for (const id of known.entries.keys()) if (!allIds.has(id)) problems.push(`js/cases/known-divergences.json has an entry for ${JSON.stringify(id)}, and no case has that id`);
const excused = []; // [{ id, fn, findings, fails }]
// The error codes each function was seen to fail with in BOTH ports, in a case the two answered
// alike: what the failure side of the coverage gate is judged on (below).
const comparedCodes = new Map();

// A member of an expected answer is the value the answer's member must be — an object or a list
// compared whole, members in any order — or a pattern its text must match where the contract fixes
// part of the words (the member a refusal names) and not all of them.
const holds = (v, got) => {
  if (v instanceof RegExp) return typeof got === 'string' && v.test(got);
  if (v !== null && typeof v === 'object') return JSON.stringify(canonical(v)) === JSON.stringify(canonical(got));
  return got === v;
};
const shown = (want) => JSON.stringify(want, (_, v) => (v instanceof RegExp ? String(v) : v));

for (const c of cases) {
  const { id, fn, args, how } = c;
  if (only && !id.includes(only) && fn !== only) continue;
  ran++;
  const t0 = performance.now();
  const [raw, rawGo] = ask(c);
  const ms = performance.now() - t0; // the two ports' answers, or nothing where a base already had them
  const fails = [];
  const said = []; // what is printed for a failure nobody excused
  for (const [port, got] of [['wasm', raw], ['go', rawGo]]) {
    if (got?.threw) { fails.push(`${port} threw`); said.push(`  THREW  ${id}  (${port}): ${got.threw}`); continue; }
    held++;
    const wrong = judge(contract, fn, args instanceof RawArgs ? args.value : args, got);
    if (wrong.length) {
      offContract++;
      fails.push(`${port} off the contract`);
      said.push(`  OFF THE CONTRACT  ${id}  (${port})`, ...wrong.slice(0, 4).map((w) => `    ${w}`));
    }
  }
  // A case that carries the spec's (or the contract's) answer is held to it; one that misses it is
  // not compared besides.
  const want = expected.get(id)?.want;
  // `decide` answers under `result`; a refusal is the answer itself.
  const judged = (got) => got?.result ?? got;
  const missed = want ? [['wasm', raw], ['go', rawGo]].filter(([, got]) => !got?.threw && Object.entries(want).some(([k, v]) => !holds(v, judged(got)?.[k]))) : [];
  for (const [port, got] of missed) {
    fails.push(`${port} not as expected`);
    said.push(`  NOT AS EXPECTED  ${id}  (${port}): want ${shown(want)}, got ${JSON.stringify(judged(got))}`);
  }
  if (!missed.length && !raw?.threw && !rawGo?.threw) {
    const a = pick(raw, how, wasm);
    const b = pick(rawGo, how, go);
    if (JSON.stringify(a) !== JSON.stringify(b)) {
      fails.push('differ');
      said.push(`  DIFFER  ${id}`, `    wasm ${JSON.stringify(a)}`, `    go   ${JSON.stringify(b)}`);
    }
  }
  const entry = known.entries.get(id);
  const v = verdict(entry, fails);
  if (v === 'pass') {
    if ((how === '*' || typeof how === 'function') && succeeded(raw)) provenWhole.add(fn);
    if (raw?.error && raw.error === rawGo?.error) {
      if (!comparedCodes.has(fn)) comparedCodes.set(fn, new Set());
      comparedCodes.get(fn).add(raw.error);
    }
    if (verbose) console.log(`  agree   ${id}`);
    results.add(id, 'PASS', { ms });
  } else if (v === 'known') {
    offExcused += fails.filter((k) => k.endsWith('off the contract')).length;
    excused.push({ id, fn, findings: entry.findings, fails });
    if (verbose) console.log(`  known   ${id}  (${entry.findings.join(', ')}: ${fails.join(', ')})`);
    results.add(id, 'PASS', { reason: `a known divergence, until ${entry.findings.join(', ')} is fixed: ${fails.join(', ')}`, ms });
  } else {
    bad++;
    const why = {
      new: `fails (${fails.join(', ')})`,
      changed: `fails (${fails.join(', ')}), and js/cases/known-divergences.json says it fails as ${[...(entry?.fails ?? [])].join(', ')}: re-read the answers, then correct the entry`,
      stale: `passes, and js/cases/known-divergences.json still excuses it (${entry?.findings.join(', ')}): delete the entry`,
    }[v];
    console.log(`  ${v === 'stale' ? 'NO LONGER DIVERGES' : v === 'changed' ? 'NOT AS ITS ENTRY SAYS' : 'FAILS'}  ${id}: ${why}`);
    for (const line of said) console.log(line);
    results.add(id, 'FAIL', { reason: why, ms });
  }
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
//      would have noticed, because a key list only ever looks at the keys someone thought to name;
//   4. every error code a function DECLARES was produced by both ports in one case they answered
//      alike. This was printed and never failed (TC-1): a declared code no case produced is either
//      reachable, and then it is a refusal nobody has compared — the audit of 2026-09-29 found 13 of
//      15 reachable with one malformed argument, and a `parse` in one port and a `bad_request` in the
//      other behind one of them — or it is not, and then declaring it is a claim nothing makes true,
//      and the fix is to the contract. So there is no list of exceptions: every declared code is
//      produced, today, by a case below.
//
// 1, and the collection's own problems (an id used twice, a case filed under the wrong section, an
// expectation for an id no case has, a base or a known divergence that names nothing), fail a
// filtered run too; 2, 3 and 4 cannot be judged on one.
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

const declared = [...contractNames].flatMap((fn) => contract.methods[fn].errors.map((c) => `${fn}/${c}`));
const unseen = declared.filter((k) => {
  const [fn, code] = k.split('/');
  return !comparedCodes.get(fn)?.has(code);
});
if (unseen.length) coverage.push(`declared and never produced by both ports in a case they answered alike, so that refusal is compared by nothing: ${unseen.join(', ')}`);

const failing = only ? problems : [...problems, ...coverage];
if (failing.length) {
  console.log('\n  THE GATE IS NOT SATISFIED');
  for (const p of failing) console.log(`    ${p}`);
}
if (only) console.log('\n  a filtered run: the coverage gate (every function has a case, one compared whole, every declared code produced) was not evaluated');
// The gate's own two verdicts, as cases of the result file, so a run of record carries them.
results.add('the collection, and the dispatchers against the contract', problems.length ? 'FAIL' : 'PASS', { reason: problems.join('; ') || null, ms: 0 });
results.add('the coverage gate', only ? 'SKIPPED' : coverage.length ? 'FAIL' : 'PASS', { reason: only ? 'a filtered run' : coverage.join('; ') || null, ms: 0 });
results.write();

// ── the manifest ───────────────────────────────────────────────────────────────────────────────
//
// `--manifest <path>` writes what was just compared, so the record of these checks is generated
// from the run rather than transcribed from it. It is written ONLY when every case agreed and the
// gate is satisfied, on an unfiltered run, so a manifest describes checks that actually held: a file
// claiming 270 passing cases cannot be produced by a run in which they did not. A known divergence
// did NOT agree: it is listed apart, with the finding it waits on, and never among the cases.
const manifestAt = process.argv[process.argv.indexOf('--manifest') + 1];
const agreed = bad === 0 && failing.length === 0;
if (process.argv.includes('--manifest') && manifestAt && !only && agreed) {
  const waiting = new Set(excused.map(({ id }) => id));
  const byFn = new Map();
  for (const { id, fn } of cases) {
    if (waiting.has(id)) continue;
    if (!byFn.has(fn)) byFn.set(fn, []);
    byFn.get(fn).push(id);
  }
  const { writeFileSync } = await import('node:fs');
  writeFileSync(manifestAt, JSON.stringify({
    generated_by: 'js/parity.mjs --manifest',
    cases: cases.length - excused.length,
    generated: made.cases.length,
    functions: surface.size,
    compared_whole: [...surface].filter((f) => whole.has(f)).length,
    disagreements: bad,
    contract: {
      file: 'contract/contract.json',
      spec: contract.spec,
      methods: contractNames.size,
      answers_validated: held,
      off_contract: offContract,
      off_contract_known: offExcused,
      declared_error_codes: declared.length,
      codes_never_produced: unseen,
    },
    by_function: [...byFn.entries()].sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([fn, ids]) => ({ fn, in_surface: surface.has(fn), compared_whole: whole.has(fn), cases: ids })),
    known_divergences: excused.map(({ id, findings, fails }) => ({ id, findings, fails })),
  }, null, 2) + '\n');
}

const total = only ? ran : cases.length;
const wholeInSurface = [...surface].filter((f) => whole.has(f)).length;
console.log(`\n${total - bad - excused.length}/${total} boundary answers agree between the ports${only ? ` (filtered by ${JSON.stringify(only)})` : `; ${surface.size} functions guarded, ${wholeInSurface} of them compared whole`} (${made.cases.length} of the cases generated from the contract)`);
console.log(`${excused.length} known divergences, each as js/cases/known-divergences.json says, waiting on the finding it names; ${bad} failures besides`);
console.log(`${held - offContract}/${held} answers hold to contract/contract.json (spec ${contract.spec}, ${contractNames.size} functions, both ports; ${offExcused} of the ${offContract} that do not are known divergences)${only ? '' : `; ${declared.length - unseen.length}/${declared.length} declared error codes were produced by both ports in a case they answered alike`}`);
// `bad` is a COUNT, and process.exit truncates mod 256: with 276 cases, exactly 256 disagreements
// would have exited 0.
process.exit(bad > 0 || failing.length ? 1 : 0);
