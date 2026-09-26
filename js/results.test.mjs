// js/results.mjs: the result file a suite writes, and the summary that fails a gate on it.
// `node --test js/results.test.mjs`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { recorder, summary } from './results.mjs';

const inDir = (fn) => {
  const dir = mkdtempSync(join(tmpdir(), 'pact-results-'));
  const before = process.env.PACT_RESULTS;
  process.env.PACT_RESULTS = dir;
  try { return fn(dir); } finally { if (before === undefined) delete process.env.PACT_RESULTS; else process.env.PACT_RESULTS = before; }
};

test('a suite writes its cases in the schema, and no two share an id', () => inDir((dir) => {
  const r = recorder('demo');
  r.add('one', 'PASS');
  r.add('one', 'FAIL', { reason: 'again', ms: 3 });
  assert.throws(() => r.add('two', 'OK'), /not a verdict/);
  const written = JSON.parse(readFileSync(r.write(), 'utf8'));
  assert.equal(written.repo, 'pact-identity');
  assert.equal(written.suite, 'demo');
  assert.equal(written.schema, 'pact-results/1');
  for (const k of ['repo', 'suite', 'tier', 'run', 'cases', 'counts']) assert.ok(k in written, k);
  for (const k of ['started', 'ended', 'commit', 'target']) assert.ok(k in written.run, `run.${k}`);
  assert.deepEqual(written.cases.map(({ id, name, verdict, evidence }) => ({ id, name, verdict, evidence })), [
    { id: 'one', name: 'one', verdict: 'PASS', evidence: [] },
    { id: 'one #2', name: 'one #2', verdict: 'FAIL', evidence: ['again'] },
  ]);
  assert.equal(written.cases[1].ms, 3);
  assert.ok(Object.keys(written).includes('run') && Object.keys(written).includes('tier'));
  assert.equal(dir, process.env.PACT_RESULTS);
}));

test('without a results directory nothing is written', () => {
  const before = process.env.PACT_RESULTS;
  delete process.env.PACT_RESULTS;
  try { const r = recorder('demo'); r.add('x', 'PASS'); assert.equal(r.write(), null); } finally { if (before !== undefined) process.env.PACT_RESULTS = before; }
});

test('the summary fails a promised suite with no file, a case that is not a PASS, and a suite of no cases', () => inDir((dir) => {
  const put = (suite, cases) => writeFileSync(join(dir, `${suite}.json`), JSON.stringify({ cases }));
  put('good', [{ id: 'a', verdict: 'PASS', ms: 1 }]);
  assert.equal(summary(dir, ['good']).ok, true);
  assert.equal(summary(dir, ['good', 'absent']).ok, false);
  assert.match(summary(dir, ['absent']).lines[0], /NO RESULT FILE/);
  put('skipped', [{ id: 'a', verdict: 'PASS' }, { id: 'b', verdict: 'SKIPPED', evidence: ['no Chrome'] }]);
  assert.equal(summary(dir, ['skipped']).ok, false, 'a case the tier promised and skipped fails it');
  put('empty', []);
  assert.equal(summary(dir, ['empty']).ok, false);
}));
