// The dispatcher readers of js/surface.mjs, held to the real sources and to what formatting can do to
// them. Every source here is changed IN MEMORY: the port files are never touched.
// `node --test js/surface.test.mjs`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { rustDispatch, goDispatch } from './surface.mjs';

const rust = readFileSync(new URL('../crates/hdtp-identity/src/api.rs', import.meta.url), 'utf8');
const go = readFileSync(new URL('../go/api.go', import.meta.url), 'utf8');
const contract = new Set(Object.keys(JSON.parse(readFileSync(new URL('../contract/contract.json', import.meta.url), 'utf8')).methods));
const sorted = (s) => [...s].sort();

// What parity.mjs used to read them with: one indentation, exactly.
const oldRust = (src) => new Set([...src.matchAll(/^\s{8}("[a-z_0-9]+"(?:\s*\|\s*"[a-z_0-9]+")*)\s*=>/gm)].flatMap((m) => m[1].split('|').map((q) => q.trim().replace(/"/g, ''))));
const oldGo = (src) => new Set([...src.matchAll(/^\t"([a-z_0-9]+)":\s/gm)].map((m) => m[1]));

test('both ports dispatch exactly the functions contract/contract.json declares', () => {
  assert.deepEqual(sorted(rustDispatch(rust)), sorted(contract));
  assert.deepEqual(sorted(goDispatch(go)), sorted(contract));
});

test('a table moved one level in is read the same, where the indentation regex read nothing', () => {
  const deeper = (src) => src.replace(/^(\s*)/gm, '$1$1    ');
  assert.deepEqual(sorted(rustDispatch(deeper(rust))), sorted(contract));
  assert.deepEqual(sorted(goDispatch(deeper(go))), sorted(contract));
  assert.equal(oldRust(deeper(rust)).size, 0, 'the old reader, shown red on the same text');
  assert.equal(oldGo(deeper(go)).size, 0);
});

test('an arm added, or taken away, is seen', () => {
  const plus = rust.replace(/("generate_key" =>)/, '"a_new_function" => json!({}),\n        $1');
  assert.ok(rustDispatch(plus).has('a_new_function'));
  const minus = rust.replace(/"prf_salt" => [^\n]*\n/, '');
  assert.ok(!rustDispatch(minus).has('prf_salt'));
  const goPlus = go.replace(/(\t"generate_key":)/, '\t"a_new_function": assembleFn,\n$1');
  assert.ok(goDispatch(goPlus).has('a_new_function'));
});

test('a string inside an arm body, a comment or a nested match is not a name', () => {
  const src = `fn dispatch(name: &str, a: &Value) -> Result<Value> {
    Ok(match name {
        // "commented_out" => nothing,
        "one" | "two" => json!({ "three": 3 }),
        "four" => match x { "five" => 5, _ => 6 },
        "six" => { let s = "seven"; r#"eight" => 8"# }
        _ => fail("nine"),
    })
}`;
  assert.deepEqual(sorted(rustDispatch(src)), ['four', 'one', 'six', 'two']);
  const gsrc = 'var functions = map[string]func(json.RawMessage) json.RawMessage{\n\t// "gone": x,\n\t"one": f(`"two": 2`),\n\t"three": func(json.RawMessage) json.RawMessage { m := map[string]int{"four": 4}; return nil },\n}';
  assert.deepEqual(sorted(goDispatch(gsrc)), ['one', 'three']);
});

test('a source with no dispatcher is an error, not an empty surface', () => {
  assert.throws(() => rustDispatch('fn other() {}'), /fn dispatch was not found/);
  assert.throws(() => goDispatch('package hdtp'), /functions map was not found/);
});
