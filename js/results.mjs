// One result file per suite, beside the console output, in the one schema every runner of the
// workspace writes (pact-gateway/docs/testing.md, "Results"):
//
//   { schema: 'pact-results/1', repo, suite, tier, run: { started, ended, commit, target },
//     cases: [{ id, name, verdict, evidence: [string], ms }], counts: { VERDICT: n } }
//
// `verdict` is PASS, FAIL, UNREACHED or SKIPPED; a case that is not a plain PASS says why as its
// first line of evidence;
// `ms` is the case's own time where the suite times each case (parity, intrude, the node --test
// suites) and the time since the suite's previous case otherwise (check, musts).
//
// Files are written only when PACT_RESULTS names a directory — gate.sh sets it to
// target/gate-results, wipes it first, and ends with `node js/results.mjs --summary <suite…>`, which
// prints one line per suite and fails when a suite it was promised wrote no file, or any case in one
// is not a PASS. PACT_RUN names the run (gate.sh sets it; otherwise the time the suite started).
import { execFileSync } from 'node:child_process';
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';

export const VERDICTS = ['PASS', 'FAIL', 'UNREACHED', 'SKIPPED'];
const started = new Date().toISOString();

/** A suite's result file, filled one case at a time and written by `write()`. */
export function recorder(suite, { tier = process.env.PACT_TIER ?? 'pre-push' } = {}) {
  const cases = [];
  const seen = new Map();
  let last = performance.now();
  return {
    /** Record one case. An id seen before in this suite gets ` #n`, so no two cases share one. */
    add(id, verdict, { reason = null, evidence, ms } = {}) {
      if (!VERDICTS.includes(verdict)) throw new Error(`results: ${verdict} is not a verdict`);
      const n = (seen.get(id) ?? 0) + 1;
      seen.set(id, n);
      const now = performance.now();
      const key = n > 1 ? `${id} #${n}` : id;
      cases.push({ id: key, name: key, verdict, evidence: [...(reason ? [reason] : []), ...(evidence ?? [])], ms: Math.round((ms ?? now - last) * 10) / 10 });
      last = now;
    },
    cases,
    write() {
      const dir = process.env.PACT_RESULTS;
      if (!dir) return null;
      const file = join(dir, `${suite}.json`);
      let commit = '';
      try { commit = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { /* not a checkout */ }
      const counts = Object.fromEntries(VERDICTS.map((v) => [v, cases.filter((c) => c.verdict === v).length]).filter(([, n]) => n));
      const doc = { schema: 'pact-results/1', repo: 'pact-identity', suite, tier, run: { started: process.env.PACT_RUN ?? started, ended: new Date().toISOString(), commit, target: '' }, cases, counts };
      writeFileSync(file, JSON.stringify(doc, null, 1) + '\n');
      return file;
    },
  };
}

/** One line per promised suite; the lines, and whether every suite wrote a file of nothing but PASS. */
export function summary(dir, suites) {
  const lines = [];
  let ok = true;
  for (const suite of suites) {
    const file = join(dir, `${suite}.json`);
    if (!existsSync(file)) { ok = false; lines.push(`${suite.padEnd(16)} NO RESULT FILE: the suite was promised and wrote none`); continue; }
    const { cases } = JSON.parse(readFileSync(file, 'utf8'));
    const count = Object.fromEntries(VERDICTS.map((v) => [v, cases.filter((c) => c.verdict === v).length]));
    const ms = cases.reduce((t, c) => t + (c.ms ?? 0), 0);
    const bad = cases.length - count.PASS;
    if (!cases.length || bad) ok = false;
    lines.push(`${suite.padEnd(16)} ${String(count.PASS).padStart(4)} PASS` + VERDICTS.slice(1).map((v) => (count[v] ? `, ${count[v]} ${v}` : '')).join('') + `  (${cases.length} cases, their own times summing to ${(ms / 1000).toFixed(1)} s)` + (cases.length ? '' : '  NO CASES'));
    for (const c of cases.filter((x) => x.verdict !== 'PASS').slice(0, 5)) lines.push(`${''.padEnd(16)}   ${c.verdict} ${c.id}${c.evidence?.[0] ? `: ${c.evidence[0]}` : ''}`);
  }
  return { lines, ok };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const i = process.argv.indexOf('--summary');
  const dir = process.env.PACT_RESULTS;
  if (i < 0 || !dir) { console.error('usage: PACT_RESULTS=<dir> node js/results.mjs --summary <suite…>'); process.exit(2); }
  const { lines, ok } = summary(dir, process.argv.slice(i + 1));
  for (const l of lines) console.log(l);
  process.exit(ok ? 0 : 1);
}
