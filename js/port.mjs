// A port is `{ kind, call(name, args) }`: the Wasm bindings in-process, or the Go binary kept open for
// the whole suite and spoken to one line of JSON per call. Both present the CONTRACT's functions by
// name, and both answer synchronously.
//
// The Go binary used to be spawned once per call — about five hundred processes for one parity run.
// It is now spawned once per suite by a worker thread (js/go-adapter.mjs); this thread blocks on an
// Atomics word until the worker has the answer, which keeps `call` synchronous for every caller
// (the defender, parity, check) without making any of them async.
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Worker, MessageChannel, receiveMessageOnPort } from 'node:worker_threads';

/** How long one call may take before the process is killed and the call is failed. */
const CALL_MS = 120_000;

/**
 * The Go adapter at `bin` as a port. `processes()` says how many adapter processes have answered so
 * far — one for a whole suite, unless one died — which is what js/port.test.mjs holds.
 */
export function adapterPort(bin, { callMs = CALL_MS } = {}) {
  const { port1, port2 } = new MessageChannel();
  const signal = new Int32Array(new SharedArrayBuffer(4));
  const worker = new Worker(new URL('./go-adapter.mjs', import.meta.url), { workerData: { bin, port: port2, signal }, transferList: [port2] });
  worker.unref();
  let next = 0;
  const pids = new Set();
  const call = (fn, args) => {
    const id = ++next;
    let seen = Atomics.load(signal, 0);
    worker.postMessage({ id, line: JSON.stringify({ fn, args: args ?? {} }) });
    const deadline = Date.now() + callMs;
    for (;;) {
      // Answers to calls that timed out earlier may still arrive; they carry an older id and are dropped.
      for (let m = receiveMessageOnPort(port1); m; m = receiveMessageOnPort(port1)) {
        if (m.message.id !== id) continue;
        if (m.message.threw) throw new Error(m.message.threw);
        pids.add(m.message.pid);
        return JSON.parse(m.message.line);
      }
      const left = deadline - Date.now();
      if (left <= 0) {
        worker.postMessage({ kill: true });
        throw new Error(`pact-identity-go gave no answer to ${fn} in ${callMs / 1000} s`);
      }
      Atomics.wait(signal, 0, seen, left);
      seen = Atomics.load(signal, 0);
    }
  };
  return { kind: 'go', call, processes: () => pids.size };
}

export async function makePort(kind = 'wasm') {
  if (kind === 'wasm') {
    const { load } = await import('./index.mjs');
    const core = await load();
    return { kind, call: core.call };
  }
  if (kind === 'go') {
    const bin = fileURLToPath(new URL('../go/bin/pact-identity-go', import.meta.url));
    return existsSync(bin) ? adapterPort(bin) : null;
  }
  throw new Error(`unknown port ${kind}`);
}

export function portFromArgv(argv = process.argv) {
  const i = argv.indexOf('--port');
  return i >= 0 ? argv[i + 1] : 'wasm';
}
