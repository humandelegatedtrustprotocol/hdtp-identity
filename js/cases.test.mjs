// The collection of parity cases (js/cases/index.mjs): what makes a set of case files a problem.
// Case files are stood in for here, so nothing in js/cases/ is touched. `node --test js/cases.test.mjs`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { collect, CASE_FILES } from './cases/index.mjs';

const contract = {
  sections: { build: 'The build', keys: 'Keys', cards: 'Cards' },
  methods: { version: { section: 'build' }, key_info: { section: 'keys' }, card_decode: { section: 'cards' } },
};
const files = ['dispatcher', 'keys', 'cards'];
const run = (bodies) => collect({}, contract, { files, importer: async (file) => ({ default: bodies[file] ?? (() => {}) }) });

test('a clean set of case files collects with no problem', async () => {
  const { cases, expected, problems } = await run({
    dispatcher: ({ add }) => { add('nobody', 'no_such_function', {}); add('a list', 'key_info', [1]); },
    keys: ({ add, expect }) => { add('key_info', 'key_info', {}); expect('key_info', { error: 'bad_request' }); },
    cards: ({ add }) => add('card_decode', 'card_decode', {}),
  });
  assert.deepEqual(problems, []);
  assert.equal(cases.length, 4);
  assert.equal(expected.get('key_info').file, 'keys');
});

test('an expectation for an id no case has is a problem: a renamed case cannot drop its spec check', async () => {
  const { problems } = await run({
    keys: ({ add, expect }) => { add('key_info, renamed', 'key_info', {}); expect('key_info', { error: 'bad_request' }); },
  });
  assert.deepEqual(problems, ['cases/keys.mjs expects an answer for "key_info", and no case has that id']);
});

test('an id used twice, even across files, is a problem', async () => {
  const { problems } = await run({
    keys: ({ add }) => add('same', 'key_info', {}),
    cards: ({ add }) => add('same', 'card_decode', {}),
  });
  assert.deepEqual(problems, ['the case id "same" is used twice (again in cases/cards.mjs)']);
});

test('a case filed under a section its function is not in is a problem', async () => {
  const { problems } = await run({
    keys: ({ add }) => add('decoded', 'card_decode', {}),
    dispatcher: ({ add }) => add('a real call', 'key_info', {}),
  });
  assert.equal(problems.length, 2);
  assert.match(problems[0], /cases\/dispatcher.mjs: "a real call" calls key_info, whose section is keys/);
  assert.match(problems[1], /cases\/keys.mjs: "decoded" calls card_decode, whose section is cards/);
});

test('a section of the contract with no case file is a problem, except the build', async () => {
  const { problems } = await collect({}, contract, { files: ['dispatcher', 'keys'], importer: async () => ({ default: () => {} }) });
  assert.deepEqual(problems, ["the contract's section cards has no case file (js/cases/cards.mjs)"]);
});

// A section's cases may be split across files: `<section>-<part>.mjs`, imported by the section's file
// and called by it. Anything else on disk is a file the collection never runs.
test('every case file on disk is one the collection runs, as a section or a part its section calls', () => {
  const onDisk = readdirSync(new URL('./cases/', import.meta.url)).filter((f) => f.endsWith('.mjs') && !['index.mjs', 'fixtures.mjs'].includes(f)).map((f) => f.slice(0, -4));
  for (const s of CASE_FILES) assert.ok(onDisk.includes(s), `js/cases/${s}.mjs is not on disk`);
  for (const f of onDisk.filter((f) => !CASE_FILES.includes(f))) {
    const section = CASE_FILES.find((s) => f.startsWith(`${s}-`));
    assert.ok(section, `js/cases/${f}.mjs is neither a section of the contract nor a part of one`);
    const src = readFileSync(new URL(`./cases/${section}.mjs`, import.meta.url), 'utf8');
    const imported = new RegExp(`^import (\\w+) from '\\./${f}\\.mjs';$`, 'm').exec(src);
    assert.ok(imported, `js/cases/${section}.mjs does not import ${f}.mjs`);
    assert.match(src, new RegExp(`^\\s*${imported[1]}\\(\\{ add, expect \\}`, 'm'), `js/cases/${section}.mjs never calls ${f}.mjs's cases`);
  }
});
