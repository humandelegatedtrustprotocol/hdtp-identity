// Every keyword `schema.mjs` enforces, held to a value that must FAIL it and one that must pass.
//
// A validator that quietly ignores a keyword is worse than no validator: the schema then states a
// constraint and nothing holds it, and the contract becomes a description of the code's bugs. Two
// properties are asserted here. Each keyword rejects what it should — a keyword silently dropped
// from `validate` makes its case pass and fails this file. And `compile` REFUSES a keyword
// `validate` does not implement, which is what makes the first property cover the whole contract
// rather than only the keywords somebody remembered to test.
//
//   node --test contract/schema.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { compile, validate, resolve } from './schema.mjs';
import { loadContract, judge, isFailure } from './contract.mjs';

/** `[keyword, schema, a value it must refuse, a value it must accept]`. */
const KEYWORDS = [
  ['type', { type: 'string' }, 3, 'x'],
  ['type, a list', { type: ['string', 'null'] }, 3, null],
  ['type integer rejects a fraction', { type: 'integer' }, 1.5, 2],
  ['type integer accepts a whole float', { type: 'integer' }, 'x', 2.0],
  ['enum', { enum: ['a', 'b'] }, 'c', 'b'],
  ['const', { const: 2 }, '2', 2],
  ['properties', { properties: { a: { type: 'string' } } }, { a: 1 }, { a: 'x' }],
  ['required', { type: 'object', properties: { a: true }, required: ['a'] }, {}, { a: 1 }],
  ['additionalProperties: false', { properties: { a: true }, additionalProperties: false }, { b: 1 }, { a: 1 }],
  ['additionalProperties: a schema', { additionalProperties: { type: 'string' } }, { b: 1 }, { b: 'x' }],
  ['items', { items: { type: 'string' } }, ['x', 2], ['x']],
  ['minItems', { minItems: 2 }, [1], [1, 2]],
  ['maxItems', { maxItems: 1 }, [1, 2], [1]],
  ['minimum', { minimum: 8192 }, 8191, 8192],
  ['maximum', { maximum: 16 }, 17, 16],
  ['minLength', { minLength: 1 }, '', 'x'],
  ['maxLength', { maxLength: 2 }, 'xxx', 'xx'],
  ['pattern', { pattern: '^[A-Za-z0-9_-]*$' }, 'a+b', 'a-b'],
  ['oneOf', { oneOf: [{ type: 'string' }, { type: 'integer' }] }, true, 'x'],
  ['anyOf', { anyOf: [{ type: 'string' }, { type: 'null' }] }, 3, null],
  ['allOf', { allOf: [{ type: 'string' }, { minLength: 2 }] }, 'x', 'xx'],
  ['$ref', { $ref: '#/$defs/S' }, 3, 'x'],
  ['false', false, 1, undefined],
];
const REF_ROOT = { $defs: { S: { type: 'string' } } };

for (const [name, schema, bad, good] of KEYWORDS) {
  test(`${name} refuses what it must, and passes what it must`, () => {
    assert.notEqual(validate(schema, bad, REF_ROOT).length, 0, `${name}: ${JSON.stringify(bad)} was accepted`);
    if (good !== undefined) assert.deepEqual(validate(schema, good, REF_ROOT), [], `${name}: ${JSON.stringify(good)} was refused`);
  });
}

test('oneOf means EXACTLY one, not at least one', () => {
  const both = { oneOf: [{ type: 'string' }, { minLength: 0 }] };
  assert.match(validate(both, 'x')[0], /matches 2 alternatives/);
});

test('a keyword this validator does not enforce is refused rather than ignored', () => {
  for (const kw of ['not', 'if', 'patternProperties', 'uniqueItems', 'multipleOf', 'format', 'exclusiveMinimum', 'prefixItems', '$dynamicRef']) {
    assert.throws(() => compile({ [kw]: {} }), (e) => e.message.includes(`keyword ${JSON.stringify(kw)} is not one this validator enforces`), `${kw} was accepted by compile`);
  }
});

test('compile refuses a $ref that names nothing, and a required member it does not describe', () => {
  assert.throws(() => compile({ $ref: '#/$defs/Nope' }), /names nothing in \$defs/);
  assert.throws(() => compile({ properties: { a: true }, required: ['b'] }), /requires "b", which it does not describe/);
  assert.throws(() => resolve('#/$defs/Nope', REF_ROOT), /names nothing/);
  assert.throws(() => compile({ type: 'strings' }), /unknown type "strings"/);
});

test('string length is counted in code points', () => {
  assert.deepEqual(validate({ maxLength: 1 }, '👋'), []); // two UTF-16 units, one character
});

// ── the contract itself ────────────────────────────────────────────────────────────────────────

const contract = await loadContract();

test('every schema in the contract compiles, and every declared error code exists', () => {
  assert.equal(Object.keys(contract.methods).length >= 39, true);
  // loadContract() throws on an unknown keyword, a dangling $ref, an undeclared section or an
  // error code that is not an ErrorCode; reaching here is the assertion.
  assert.equal(contract.spec.length > 0, true);
});

test('a failure is recognised by its shape, not by a member called error', () => {
  assert.equal(isFailure({ error: 'parse', why: 'not base64url' }), true);
  // `profile_error` answers `{"error": null}` and `{"error": "<words>"}` as its RESULT.
  assert.equal(isFailure({ error: null }), false);
  assert.equal(isFailure({ error: 'serial not 64-160 bits positive' }), false);
  assert.deepEqual(judge(contract, 'profile_error', { der: 'AAAA', kind: 'root' }, { error: 'over 4 KiB' }), []);
});

test('judge catches a member the contract does not describe, and one that is missing', () => {
  const args = { spki: 'AAAA' };
  assert.match(judge(contract, 'key_info', args, { alg: 'ed25519', fingerprint: 'sha256:' + 'A'.repeat(43), key_id: 'AA', extra: 1 })[0], /does not describe/);
  assert.match(judge(contract, 'key_info', args, { alg: 'ed25519', fingerprint: 'sha256:' + 'A'.repeat(43) })[0], /has no member "key_id"/);
});

test('judge catches an undeclared error code, and an unknown function that does not say unsupported', () => {
  assert.match(judge(contract, 'key_info', {}, { error: 'vault', why: 'x' })[0], /which the contract does not declare/);
  assert.match(judge(contract, 'no_such_function', {}, { error: 'parse', why: 'x' })[0], /not "unsupported"/);
  assert.deepEqual(judge(contract, 'no_such_function', {}, { error: 'unsupported', why: 'no function named no_such_function' }), []);
});

test('null is absent: a member given as null does not fail its schema', () => {
  // §0. `{"root_spkis": null}` is "no roots to refuse against", not a list that is not a list.
  assert.deepEqual(judge(contract, 'csr_check', { der: 'AAAA', root_spkis: null }, { ok: false, why: 'x' }), []);
});
