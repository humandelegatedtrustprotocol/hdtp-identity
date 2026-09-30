// A port is `{ kind, call(name, args) }`: the Wasm bindings in-process, or the Go binary kept open for
// the whole suite and spoken to one line of JSON per call. Both present the CONTRACT's functions by
// name, and both answer synchronously.
//
// The Go binary used to be spawned once per call — about five hundred processes for one parity run.
// It is now spawned once per suite by a worker thread (js/go-adapter.mjs); this thread blocks on an
// Atomics word until the worker has the answer, which keeps `call` synchronous for every caller
// (the defender, parity, check) without making any of them async.
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { Worker, MessageChannel, receiveMessageOnPort } from 'node:worker_threads';

/**
 * Arguments sent as the JSON text given, byte for byte, to both ports: what `JSON.stringify` cannot
 * write — a number outside a double's range (`1e400`), `-0`, an integer spelled `8192.0` — and so
 * what no other case can ask either port about. One line of text: the Go adapter reads a request per
 * line. `value` is the text as JavaScript reads it, for the contract's judge; `toJSON` keeps a writer
 * that meets one from recording `{}` for it.
 */
export class RawArgs {
  constructor(text) {
    if (typeof text !== 'string' || /[\r\n]/.test(text)) throw new Error('raw arguments are one line of JSON text');
    this.text = text;
  }
  get value() {
    try { return JSON.parse(this.text); } catch { return undefined; }
  }
  toJSON() {
    return { raw: this.text };
  }
  /** `args` as JSON text, with `from` — which must be in it exactly once — written as `to`. */
  static edit(args, from, to) {
    const text = JSON.stringify(args);
    if (text.split(from).length !== 2) throw new Error(`raw arguments: ${from} is not in the text exactly once`);
    return new RawArgs(text.replace(from, () => to));
  }
}

/** The request line the Go adapter reads: `args` as given, or as written when it is raw text. */
export const requestLine = (fn, args) =>
  args instanceof RawArgs ? `{"fn":${JSON.stringify(fn)},"args":${args.text}}` : JSON.stringify({ fn, args: args === undefined ? {} : args });

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
    // `args` goes as it is given: `null`, a list or a scalar reach the port, which is what the
    // dispatcher's cases ask it about. Only a call with no arguments at all is `{}`.
    worker.postMessage({ id, line: requestLine(fn, args) });
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
    // Raw text goes to the module the loader wraps (the same instance, from require's cache): the
    // loader takes arguments as a value, and a value cannot hold what raw text is for.
    const mod = createRequire(import.meta.url)('./pkg-node/pact_identity_wasm.js');
    return { kind, call: (fn, args) => (args instanceof RawArgs ? JSON.parse(mod.call(fn, args.text)) : core.call(fn, args)) };
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
