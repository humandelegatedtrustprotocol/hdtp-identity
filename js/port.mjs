// A port is `{ kind, call(name, args) }`: the Wasm bindings in-process, or the Go binary one
// request at a time over stdin/stdout. Both present the CONTRACT's functions by name.
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

export async function makePort(kind = 'wasm') {
  if (kind === 'wasm') {
    const { load } = await import('./index.mjs');
    const core = await load();
    return { kind, call: core.call };
  }
  if (kind === 'go') {
    const bin = new URL('../go/bin/pact-identity-go', import.meta.url).pathname;
    if (!existsSync(bin)) return null;
    return {
      kind,
      call: (fn, args) => {
        const r = spawnSync(bin, [], { input: JSON.stringify({ fn, args: args ?? {} }), encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
        if (r.error) throw r.error;
        if (r.status !== 0) throw new Error(`pact-identity-go exited ${r.status}: ${r.stderr}`);
        return JSON.parse(r.stdout);
      },
    };
  }
  throw new Error(`unknown port ${kind}`);
}

export function portFromArgv(argv = process.argv) {
  const i = argv.indexOf('--port');
  return i >= 0 ? argv[i + 1] : 'wasm';
}
