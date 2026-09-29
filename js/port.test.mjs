// The Go port's adapter is one process per suite, and a process that dies costs one call, not the
// rest of the suite. `node --test js/port.test.mjs`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { adapterPort, makePort, RawArgs } from './port.mjs';

const real = fileURLToPath(new URL('../go/bin/pact-identity-go', import.meta.url));

/** A stand-in adapter: answers `{"ok":true,"n":<line number>}`, dies on a request naming `die`, hangs on `hang`. */
function fake() {
  const dir = mkdtempSync(join(tmpdir(), 'pact-port-'));
  const bin = join(dir, 'adapter');
  writeFileSync(bin, [
    '#!/bin/sh',
    'n=0',
    'while IFS= read -r line; do',
    '  n=$((n+1))',
    '  case "$line" in',
    '    *\\"die\\"*) echo "dying" >&2; exit 3 ;;',
    '    *\\"hang\\"*) sleep 30 ;;',
    '  esac',
    '  echo "{\\"ok\\":true,\\"n\\":$n}"',
    'done',
    '',
  ].join('\n'));
  chmodSync(bin, 0o755);
  return bin;
}

test('a whole suite of calls is answered by ONE adapter process', { skip: !existsSync(real) && 'go/bin/pact-identity-go is not built' }, () => {
  const port = adapterPort(real);
  for (let i = 0; i < 50; i++) assert.equal(port.call('prf_salt', {}).infos.length, 3);
  assert.equal(port.processes(), 1);
});

test('answers come back to the call that asked, in order', () => {
  const port = adapterPort(fake());
  assert.deepEqual([1, 2, 3].map(() => port.call('x', {}).n), [1, 2, 3]);
});

test('a process that dies fails the call it was holding, and the next call gets a new one', () => {
  const port = adapterPort(fake());
  assert.equal(port.call('x', {}).n, 1);
  assert.throws(() => port.call('die', {}), /exited 3: dying/);
  assert.equal(port.call('x', {}).n, 1, 'the next call is the first line of a NEW process');
  assert.equal(port.processes(), 2);
});

test('a call that hangs is failed at its deadline, and the port goes on', () => {
  // The deadline also covers the NEXT call, which starts a new process: 500 ms was enough alone and
  // not under the gate, where every suite runs at once (a gate run of 2026-09-27 failed here with
  // "gave no answer to x in 0.5 s", the fresh process still starting). A margin, not a boundary.
  const port = adapterPort(fake(), { callMs: 3000 });
  assert.throws(() => port.call('hang', {}), /gave no answer to hang/);
  assert.equal(port.call('x', {}).n, 1, 'the hung process was killed and a new one answers');
});

// Raw arguments are what the cases cannot say as a value — `1e400`, `-0`, `8192.0` — so they are
// worth something only if the text arrives as written. JSON.stringify of the value would send
// `{"x":null}` for `{"x":1e400}`, and `0` for `-0`.
test('raw arguments reach both ports as the text written, byte for byte', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pact-raw-'));
  const echo = join(dir, 'adapter');
  // A stand-in adapter that answers with the request line it read, in base64.
  writeFileSync(echo, ['#!/bin/sh', 'while IFS= read -r line; do', `  printf '{"line":"%s"}\\n' "$(printf '%s' "$line" | base64 | tr -d '\\n')"`, 'done', ''].join('\n'));
  chmodSync(echo, 0o755);
  const text = '{"x":1e400,"y":-0,"z":8192.0}';
  const line = Buffer.from(adapterPort(echo).call('f', new RawArgs(text)).line, 'base64').toString();
  assert.equal(line, `{"fn":"f","args":${text}}`);
  const wasm = await makePort('wasm');
  const out = wasm.call('version', new RawArgs('{"x":1e400}'));
  assert.equal(out.error, 'bad_request');
  assert.notEqual(out.why, 'version takes no member "x"', 'the core was handed the value, not the text');
  assert.throws(() => new RawArgs('{"x":\n1}'), /one line/);
  assert.throws(() => RawArgs.edit({ a: 1, b: 1 }, ':1', ':2'), /exactly once/);
  assert.equal(RawArgs.edit({ a: 1, b: 2 }, '"b":2', '"b":-0').text, '{"a":1,"b":-0}');
  assert.equal(JSON.stringify(new RawArgs('{}')), '{"raw":"{}"}');
});
