// The divergences the generated cases (js/cases/generated.mjs) found on the day they were written,
// each naming the audit finding that will close it: js/cases/known-divergences.json.
//
// The generated cases were written before any of the defects behind them was fixed (the port-parity
// plan of 2026-09-29, §1 rule 2: the guard first, shown red on the code as it was, so the guard is
// what proves the fixes). Hundreds of them fail today. So that each commit on the way stays green and
// pushable, a case that fails EXACTLY as its entry says is excused, and nothing else is:
//
//   a case that fails with no entry                         fails the run (a new divergence);
//   a case that fails otherwise than its entry says         fails the run (the entry is out of date);
//   a case that passes and still has an entry               fails the run (delete the entry);
//   an entry naming a case no run has                        fails the run;
//   a port that threw                                        is never excused.
//
// So the list can only shrink. The stage that fixes a finding deletes its entries, because the run
// refuses them the moment the cases pass; the last stage deletes this file, the list and every use
// of them (no compatibility path).

/** How a case can fail, as js/parity.mjs names it. An entry's `fails` is a set of these. */
export const FAILS = ['wasm off the contract', 'go off the contract', 'wasm not as expected', 'go not as expected', 'differ'];

/** An audit finding's id (report.md), or a divergence the generated cases found that the audit did not. */
const FINDING = /^(?:F|X|R|C|N|T)\d+$|^(?:TC|CW)-\d+$|^S1-\d+$/;

/**
 * The list, read and held to its own shape: `{ entries: Map(id -> { findings, fails }), problems }`.
 * `json` is the parsed file, for a test to hand in.
 */
export function readKnown(json) {
  const problems = [];
  const entries = new Map();
  const described = new Set(Object.keys(json.new_findings ?? {}));
  const used = new Set();
  for (const [id, e] of Object.entries(json.cases ?? {})) {
    const where = `js/cases/known-divergences.json: ${JSON.stringify(id)}`;
    if (!Array.isArray(e?.findings) || !e.findings.length) { problems.push(`${where} names no finding`); continue; }
    const bad = e.findings.filter((f) => !FINDING.test(f));
    if (bad.length) problems.push(`${where} names ${bad.join(', ')}, which is not a finding's id`);
    for (const f of e.findings) if (f.startsWith('S1-')) used.add(f);
    const fails = Array.isArray(e.fails) ? e.fails : [];
    const unknown = fails.filter((k) => !FAILS.includes(k));
    if (!fails.length || unknown.length || new Set(fails).size !== fails.length) {
      problems.push(`${where} says it fails as ${JSON.stringify(e.fails)}: a set of ${FAILS.join(' | ')}`);
      continue;
    }
    entries.set(id, { findings: e.findings, fails: new Set(fails) });
  }
  for (const f of used) if (!described.has(f)) problems.push(`js/cases/known-divergences.json names ${f}, and new_findings does not say what it is`);
  for (const f of described) if (!used.has(f)) problems.push(`js/cases/known-divergences.json describes ${f}, and no entry names it`);
  return { entries, problems };
}

/**
 * What one case's run makes of its entry. `fails` is how the case failed this run (FAILS, plus
 * `wasm threw` / `go threw`), empty when it passed:
 *   pass     it passed, and has no entry;
 *   known    it failed exactly as its entry says;
 *   new      it failed, and has no entry — or a port threw, which no entry excuses;
 *   changed  it failed, and not as its entry says;
 *   stale    it passed, and still has an entry.
 */
export function verdict(entry, fails) {
  if (!fails.length) return entry ? 'stale' : 'pass';
  if (!entry || fails.some((k) => !FAILS.includes(k))) return 'new';
  return fails.length === entry.fails.size && fails.every((k) => entry.fails.has(k)) ? 'known' : 'changed';
}
