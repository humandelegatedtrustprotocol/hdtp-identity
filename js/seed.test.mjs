// js/seed.mjs: the one reading of the seed's intrusion output and of Appendix B. `node --test js/seed.test.mjs`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseIntrusions, seedIntrusions, appendixB } from './seed.mjs';

test('the seed output parses to its scenarios, and a count that does not add up is refused', () => {
  const out = 'identity\n  blocked    one  → x\n  residual   two\n  REPRODUCES three  → y\n\n3 scenarios: 1 blocked, 1 residual by decision, 1 reproduce\n';
  assert.deepEqual(parseIntrusions(out), { scenarios: [{ name: 'one', verdict: 'blocked' }, { name: 'two', verdict: 'residual' }, { name: 'three', verdict: 'REPRODUCES' }], total: 3 });
  assert.throws(() => parseIntrusions(out.replace('3 scenarios', '4 scenarios')), /reports 4 scenarios and printed 3/);
  assert.throws(() => parseIntrusions('nothing here\n'), /printed no scenarios/);
});

test('within one results directory the seed runs once, and a changed input runs it again', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pact-seed-'));
  const before = process.env.PACT_RESULTS;
  process.env.PACT_RESULTS = dir;
  try {
    const first = seedIntrusions();
    assert.equal(first.status, 0);
    assert.ok(first.total > 0 && first.total === first.scenarios.length);
    const file = join(dir, 'seed-intrude.json');
    const kept = JSON.parse(readFileSync(file, 'utf8'));
    writeFileSync(file, JSON.stringify({ ...kept, marker: 'from the cache' }));
    assert.equal(seedIntrusions().marker, 'from the cache', 'the second call read the kept answer');
    writeFileSync(file, JSON.stringify({ ...kept, key: 'inputs that are not these', marker: 'stale' }));
    assert.equal(seedIntrusions().marker, undefined, 'an answer kept for other inputs is not used');
  } finally {
    if (before === undefined) delete process.env.PACT_RESULTS; else process.env.PACT_RESULTS = before;
  }
});

// js/appendix-b-reader.json: the cases all four Appendix B readers of this repository are held to.
test('Appendix B is read as js/appendix-b-reader.json says, refusals word for word', () => {
  const { cases } = JSON.parse(readFileSync(new URL('./appendix-b-reader.json', import.meta.url), 'utf8'));
  assert.ok(cases.length >= 10);
  for (const c of cases) {
    if (c.refused) assert.throws(() => appendixB(c.doc), (e) => e.message === c.refused, c.name);
    else assert.deepEqual(appendixB(c.doc), c.blocks, c.name);
  }
});

// Two repositories keep this list, and each holds its own readers to its own copy: pact-protocol's
// vectors/check.mjs holds the checker's and the splicer's reader to vectors/appendix-b-reader.json.
// The two copies are held to each other here, byte for byte, from the pact-protocol checked out
// beside this repository, as the gate reads it (TC-12): a case added to one list alone fails.
test('the Appendix B cases are the same bytes in pact-protocol\'s copy', () => {
  const mine = readFileSync(new URL('./appendix-b-reader.json', import.meta.url));
  const theirs = readFileSync(new URL('../../pact-protocol/vectors/appendix-b-reader.json', import.meta.url));
  assert.ok(mine.equals(theirs), 'js/appendix-b-reader.json and pact-protocol vectors/appendix-b-reader.json differ');
});

test('the specification\'s first block is the seed\'s vector file, unchanged', () => {
  const spec = readFileSync(new URL('../../pact-protocol/SPEC.md', import.meta.url), 'utf8');
  const file = JSON.parse(readFileSync(new URL('../../pact-protocol/vectors/pact-2.0-vectors.json', import.meta.url), 'utf8'));
  assert.deepEqual(appendixB(spec)[0], file);
});
