// scripts/spec-patterns.mjs against stand-in hdtp-spec checkouts: what it prints for a pattern that
// travels as written, and what it refuses because it would not. The real sibling checkout is the
// control that must get through.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../', import.meta.url));
const script = join(repo, 'scripts/spec-patterns.mjs');

function spec({ article = '/\\b[Aa] HDTP/g', local = '/\\/srv\\/|(^|[^a-z])\\/opt\\/[a-z]+/' } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'hdtp-spec-patterns-'));
  mkdirSync(join(dir, 'vectors/lib'), { recursive: true });
  mkdirSync(join(dir, 'scripts'));
  writeFileSync(join(dir, 'vectors/lib/stated.mjs'), `export const ARTICLE = ${article}\n`);
  writeFileSync(join(dir, 'scripts/local-paths.mjs'), `const LOCAL = ${local}\n\nexport function localPaths() {}\n`);
  return dir;
}

const run = (dir, which) => spawnSync(process.execPath, [script, dir, which], { encoding: 'utf8' });

function refused(dir, which, why) {
  const r = run(dir, which);
  assert.equal(r.status, 2, `exit ${r.status}, stdout ${JSON.stringify(r.stdout)}, stderr ${JSON.stringify(r.stderr)}`);
  assert.equal(r.stdout, '');
  assert.match(r.stderr, why);
}

test('the real sibling hdtp-spec gets through, both patterns', () => {
  for (const which of ['article', 'local']) {
    const r = run(join(repo, '../hdtp-spec'), which);
    assert.equal(r.status, 0, r.stderr);
    assert.notEqual(r.stdout, '');
  }
});

test('patterns with no flag or with g are printed as written, LOCAL with \\/ unescaped', () => {
  for (const flags of ['', 'g']) {
    const dir = spec({ article: `/\\b[Aa] HDTP/${flags}`, local: `/\\/srv\\/|(^|[^a-z])\\/opt\\/[a-z]+/${flags}` });
    assert.deepEqual([run(dir, 'article').stdout, run(dir, 'local').stdout], ['\\b[Aa] HDTP', '/srv/|(^|[^a-z])/opt/[a-z]+']);
  }
});

test('a LOCAL with a (?…) group is refused: git grep -E exits 128 on it', () => {
  refused(spec({ local: '/(?:\\/srv)\\/|\\/opt\\/[a-z]+/' }), 'local', /LOCAL carries a group \(\?…\) or a lazy quantifier/);
  refused(spec({ local: '/\\/srv\\/(?=x)/' }), 'local', /LOCAL carries a group \(\?…\) or a lazy quantifier/);
});

test('a LOCAL with a lazy quantifier is refused', () => {
  for (const q of ['*?', '+?', '??', '{1,3}?']) {
    refused(spec({ local: `/\\/srv\\/[a-z]${q}x/` }), 'local', /LOCAL carries a group \(\?…\) or a lazy quantifier/);
  }
});

test('a LOCAL with a backslash other than \\/ is still refused', () => {
  refused(spec({ local: '/\\/srv\\/\\d+/' }), 'local', /LOCAL carries a backslash other than/);
});

test('a flag other than g is refused on either pattern', () => {
  for (const flags of ['i', 'gi', 'm', 'u', 's', 'y']) {
    refused(spec({ local: `/\\/srv\\//${flags}` }), 'local', /LOCAL carries a flag other than g/);
    refused(spec({ article: `/\\b[Aa] HDTP/${flags}` }), 'article', /ARTICLE carries a flag other than g/);
  }
});
