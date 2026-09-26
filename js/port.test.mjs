// The Go port's adapter is one process per suite, and a process that dies costs one call, not the
// rest of the suite. `node --test js/port.test.mjs`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { adapterPort } from './port.mjs';

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
  const port = adapterPort(fake(), { callMs: 500 });
  assert.throws(() => port.call('hang', {}), /gave no answer to hang/);
  assert.equal(port.call('x', {}).n, 1, 'the hung process was killed and a new one answers');
});
