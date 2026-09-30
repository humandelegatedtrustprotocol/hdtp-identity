// The collection of parity cases (js/cases/index.mjs): what makes a set of case files a problem.
// Case files are stood in for here, so nothing in js/cases/ is touched. `node --test js/cases.test.mjs`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { collect, CASE_FILES } from './cases/index.mjs';
import { generate, pickBases, wrongTypeFor, wrongTypeAnswer, keyedOf, refuses, BASES, EMPTY_IS_A_VALUE, HOSTILE, READ_FOR_WHAT_IT_NEEDS, UNDECLARED } from './cases/generated.mjs';

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
  // index collects, fixtures feeds, and generated makes cases from the contract: none of them is a
  // section's cases.
  const onDisk = readdirSync(new URL('./cases/', import.meta.url)).filter((f) => f.endsWith('.mjs') && !['index.mjs', 'fixtures.mjs', 'generated.mjs'].includes(f)).map((f) => f.slice(0, -4));
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

// ── the generated cases (js/cases/generated.mjs) ─────────────────────────────────────────────────
const small = {
  $defs: { B64url: { type: 'string' } },
  sections: { build: 'The build', keys: 'Keys' },
  methods: {
    version: { section: 'build', params: { type: 'object', properties: {} }, errors: [] },
    sign: {
      section: 'keys',
      params: { type: 'object', properties: { pkcs8: { $ref: '#/$defs/B64url' }, data: { type: 'string' }, deep: { type: 'boolean' } }, required: ['pkcs8', 'data'] },
      errors: ['bad_request'],
    },
  },
};

test('every function gets {} and the hostile members it declares; one with a base gets each shape of a mistake, from the contract', () => {
  const base = { id: 'sign', fn: 'sign', args: { pkcs8: 'AA', data: 'BB' }, how: '*' };
  const { cases, expected } = generate(small, new Map([['sign', base]]));
  const byId = new Map(cases.map((c) => [c.id.replace('generated · sign · ', ''), c]));
  // `sign` declares none of the hostile object's members: sent whole, the object would be refused for
  // its first undeclared member before any member is read, so there is no such case (`{}` is it).
  assert.deepEqual([...byId.keys()], [
    '{}',
    'pkcs8 absent', 'pkcs8 null', 'pkcs8 ""', 'data absent', 'data null', 'data ""',
    'deep "yes"',
    'an undeclared member',
    'pkcs8 absent, data 7', 'pkcs8 absent, deep "yes"', 'data absent, pkcs8 7', 'data absent, deep "yes"',
  ]);
  assert.ok(!cases.some((c) => c.fn === 'version'), 'version describes the port and is not compared');
  // A function that declares some of them is sent those, and only those.
  const withNow = structuredClone(small);
  withNow.methods.sign.params.properties.now = { type: 'string' };
  const hostile = generate(withNow, new Map()).cases.find((c) => c.id === 'generated · sign · the hostile object');
  assert.deepEqual(hostile.args, { now: HOSTILE.now });
  assert.deepEqual(byId.get('pkcs8 absent').args, { data: 'BB' });
  assert.deepEqual(byId.get('pkcs8 null').args, { pkcs8: null, data: 'BB' });
  assert.deepEqual(byId.get('data absent, pkcs8 7').args, { pkcs8: 7 });
  assert.equal(byId.get('an undeclared member').args.not_a_member, 1);
  // §0's answer for an absent member, and for null, which is absent; and for an optional member of
  // the wrong type, which is refused in words that name it and never read as absent.
  assert.deepEqual(expected.get('generated · sign · data null'), { error: 'bad_request', why: 'data is required' });
  assert.deepEqual(expected.get('generated · sign · deep "yes"'), { error: 'bad_request', why: /\bdeep\b/ });
  // A required string is sent "" and judged: it must refuse, unless EMPTY_IS_A_VALUE names it with why.
  // `sign.data` is on that list (the bytes to sign), `sign.pkcs8` is not.
  const pkcs8Empty = expected.get('generated · sign · pkcs8 ""'), dataEmpty = expected.get('generated · sign · data ""');
  assert.ok('sign.data' in EMPTY_IS_A_VALUE && !('sign.pkcs8' in EMPTY_IS_A_VALUE));
  assert.equal(pkcs8Empty({ error: 'parse', why: 'DER truncated' }), true);
  assert.equal(pkcs8Empty({ sig: 'AA' }), false);
  assert.equal(dataEmpty({ sig: 'AA' }), true);
  assert.equal(dataEmpty({ error: 'parse', why: 'DER truncated' }), false);
  assert.equal(expected.size, 7);
});

test('a refusal is judged in its function\'s own shape, and profile_error\'s {error: null} is an answer', () => {
  for (const a of [{ error: 'parse', why: 'x' }, { ok: false, why: 'x' }, { follow: false, why: 'x' }, { result: { code: 'envelope_invalid', why: 'x' }, effects: [] }]) assert.equal(refuses(a), true, JSON.stringify(a));
  for (const a of [{ error: null }, { error: 'a profile error' }, { ok: true }, { follow: true }, { valid: false }, { normal: false }, { result: { code: 'ok' }, effects: [] }]) assert.equal(refuses(a), false, JSON.stringify(a));
});

test('a name on EMPTY_IS_A_VALUE that is no required string member fails the run', () => {
  const { problems } = generate(small, new Map());
  assert.ok(problems.some((p) => /EMPTY_IS_A_VALUE names build_root\.cn, which is not a required member that takes a string/.test(p)), problems.join('\n'));
  assert.ok(!problems.some((p) => / sign\.data,/.test(p)), 'sign.data is a required string member of the small contract');
});

test('a member undeclared inside a member is judged by CONTRACT §0: a document refuses it, a host\'s state reads past it', () => {
  // `decide node` is on READ_FOR_WHAT_IT_NEEDS and `sign held` is not: a small contract with both.
  const two = {
    ...small,
    methods: {
      ...small.methods,
      sign: { ...small.methods.sign, params: { ...small.methods.sign.params, properties: { ...small.methods.sign.params.properties, held: { type: 'object' } } } },
      decide: { section: 'keys', params: { type: 'object', properties: { node: { type: 'object' } }, required: ['node'] }, errors: ['bad_request'] },
    },
  };
  const bases = new Map([
    ['sign', { id: 'sign', fn: 'sign', args: { pkcs8: 'AA', data: 'BB', held: { a: 1 } }, how: '*' }],
    ['decide', { id: 'decide', fn: 'decide', args: { node: { endpoint: 'e', pins: [{ root: 'r' }] } }, how: '*' }],
  ]);
  const { cases, expected, problems } = generate(two, bases);
  const at = (id) => cases.find((c) => c.id === `generated · ${id}`);
  const document = expected.get('generated · sign · an undeclared member in held');
  assert.deepEqual(at('sign · an undeclared member in held').args.held, { a: 1, [UNDECLARED]: 1 });
  assert.equal(at('sign · an undeclared member in held').described, undefined, 'a document is judged on what was sent');
  assert.equal(document({ error: 'bad_request', why: 'held holds a, and nothing else: not_a_member' }), true);
  assert.equal(document({ sig: 'AA' }), false);
  assert.ok(READ_FOR_WHAT_IT_NEEDS.has('decide node'));
  const state = expected.get('generated · decide · an undeclared member in node');
  assert.equal(state({ result: { code: 'ok' }, effects: [] }), true);
  assert.equal(state({ error: 'bad_request', why: 'node holds …' }), false);
  // Read past, the call is held to the contract as the base's arguments, without the added member.
  assert.deepEqual(at('decide · an undeclared member in node').described, bases.get('decide').args);
  // decide's pins.0 is a list's first entry, and on the list too; its base reaches it.
  assert.ok(expected.has('generated · decide · an undeclared member in node.pins.0'));
  // The rest of READ_FOR_WHAT_IT_NEEDS names functions this contract does not have, or ones with no base.
  assert.ok(problems.some((p) => /READ_FOR_WHAT_IT_NEEDS names refresh_check pin, and the contract has no refresh_check/.test(p)), problems.join('\n'));
  assert.ok(problems.some((p) => /READ_FOR_WHAT_IT_NEEDS names decide envelope, which no generated case reaches/.test(p)), problems.join('\n'));
  assert.ok(!problems.some((p) => /names decide node[ ,]/.test(p)), problems.join('\n'));
});

test('an optional member of the wrong type is held to §0: bytes do not decode, anything else is named', () => {
  const root = { $defs: { B64url: { type: 'string' }, Serial: { $ref: '#/$defs/B64url' }, Form: { enum: ['chain', 'leaf'] } } };
  const bytes = { error: 'parse', why: 'not base64url' };
  assert.deepEqual(wrongTypeAnswer('aad', { $ref: '#/$defs/B64url' }, root), bytes);
  assert.deepEqual(wrongTypeAnswer('serial', { $ref: '#/$defs/Serial' }, root), bytes);
  const named = wrongTypeAnswer('exp', { type: 'integer' }, root);
  assert.equal(named.error, 'bad_request');
  assert.ok(named.why.test('exp is required') && named.why.test('the record\'s exp is a list'));
  assert.ok(!named.why.test('expected_root is required'), 'the member by its whole name, not a prefix of another');
  assert.equal(wrongTypeAnswer('form', { $ref: '#/$defs/Form' }, root).error, 'bad_request');
});

test('an optional string is also tried as "", and a wrong type is one the member does not admit', () => {
  const withOptional = structuredClone(small);
  withOptional.methods.sign.params.properties.label = { type: 'string' };
  const { cases } = generate(withOptional, new Map([['sign', { id: 'sign', fn: 'sign', args: { pkcs8: 'AA', data: 'BB' }, how: '*' }]]));
  const ids = cases.map((c) => c.id);
  assert.ok(ids.includes('generated · sign · label ""'));
  assert.ok(ids.includes('generated · sign · label 7'));
  const root = { $defs: {} };
  assert.equal(wrongTypeFor({ type: 'string' }, root), 7);
  assert.equal(wrongTypeFor({ type: 'boolean' }, root), 'yes');
  assert.equal(wrongTypeFor({ type: 'integer' }, root), '7');
  assert.equal(wrongTypeFor({ type: 'object' }, root), 'x');
  assert.equal(wrongTypeFor({ type: 'array' }, root), 'x');
  assert.deepEqual(wrongTypeFor({ type: ['string', 'integer'] }, root), {});
  assert.equal(wrongTypeFor(true, root), undefined);
});

test('every member that holds a key gets one outside the profile, in the first place of a list', () => {
  const $defs = {
    B64url: { type: 'string' }, Spki: { $ref: '#/$defs/B64url' }, Pkcs8: { $ref: '#/$defs/B64url' }, CertDer: { $ref: '#/$defs/B64url' },
    Csr: { $ref: '#/$defs/B64url' }, Chain: { type: 'array', items: { $ref: '#/$defs/CertDer' } }, Node: { type: 'object', properties: { pkcs8: { $ref: '#/$defs/Pkcs8' } } },
  };
  const root = { $defs };
  assert.deepEqual(keyedOf({ $ref: '#/$defs/Spki' }, root), { type: 'Spki', list: false });
  assert.deepEqual(keyedOf({ $ref: '#/$defs/Chain' }, root), { type: 'CertDer', list: true });
  assert.deepEqual(keyedOf({ type: 'array', items: { $ref: '#/$defs/Spki' } }, root), { type: 'Spki', list: true });
  assert.equal(keyedOf({ $ref: '#/$defs/B64url' }, root), null, 'bytes are not a key');
  assert.equal(keyedOf({ $ref: '#/$defs/Node' }, root), null, 'a key inside an object is its reader\'s, not a member');
  const contract = {
    $defs, sections: { keys: 'Keys' },
    methods: { seal: { section: 'keys', params: { type: 'object', properties: { spki: { $ref: '#/$defs/Spki' }, chain: { $ref: '#/$defs/Chain' }, roots: { type: 'array', items: { $ref: '#/$defs/Spki' } }, data: { $ref: '#/$defs/B64url' } }, required: ['spki', 'data'] }, errors: ['bad_request'] } },
  };
  const base = { id: 'seal', fn: 'seal', args: { spki: 'S', chain: ['L', 'R'], data: 'D' }, how: '*' };
  const outside = { Spki: 'out-spki', Pkcs8: 'out-pkcs8', CertDer: 'out-cert', Csr: 'out-csr' };
  const made = generate(contract, new Map([['seal', base]]), outside).cases.filter((c) => c.kind === 'a key outside the profile');
  assert.deepEqual(made.map((c) => [c.id, c.args]), [
    ['generated · seal · spki holding a key outside the profile', { spki: 'out-spki', chain: ['L', 'R'], data: 'D' }],
    ['generated · seal · chain holding a key outside the profile', { spki: 'S', chain: ['out-cert', 'R'], data: 'D' }],
    ['generated · seal · roots holding a key outside the profile', { spki: 'S', chain: ['L', 'R'], data: 'D', roots: ['out-spki'] }],
  ]);
  assert.equal(generate(contract, new Map([['seal', base]])).cases.filter((c) => c.kind === 'a key outside the profile').length, 0, 'no values, no shape');
});

test('a base is named, found, of its function, and succeeds on both ports, or the run is told why', () => {
  const contract = { methods: { version: { section: 'build' }, sign: { section: 'keys' } } };
  const ok = (a) => !a.error;
  const ask = (c) => c.answers;
  const named = BASES.sign;
  assert.ok(pickBases(contract, [], ask, ok).problems.includes(`js/cases/generated.mjs names ${JSON.stringify(named)} as sign's base, and no case has that id`));
  const refused = { id: named, fn: 'sign', answers: [{}, { error: 'bad_request' }] };
  assert.match(pickBases(contract, [refused], ask, ok).problems.join('\n'), /sign's base "sign" does not succeed on both ports/);
  const other = { id: named, fn: 'verify', answers: [{}, {}] };
  assert.match(pickBases(contract, [other], ask, ok).problems.join('\n'), /as sign's base, and it calls verify/);
  const good = { id: named, fn: 'sign', answers: [{}, {}] };
  const picked = pickBases(contract, [good], ask, ok);
  assert.equal(picked.bases.get('sign'), good);
  // Every other name in BASES is a function this small contract does not declare: each is a problem.
  assert.equal(picked.problems.length, Object.keys(BASES).length - 1);
});
