// A fresh instance of the Wasm core, with its linear memory in view: test tooling for
// js/export-memory.test.mjs. Each call to `fresh()` starts a worker thread of its own, which loads
// the node package's glue unchanged and so builds a new instance; while it loads,
// `WebAssembly.Instance` is a function that builds the real one and records it, because the glue
// keeps its instance to itself. A measurement therefore starts from the core's own starting size and
// reads the memory of the instance the glue's `call` runs on. The worker answers each request while
// the caller waits on a shared flag, so `call` and `bytes` stay synchronous; `close` ends the worker
// and frees its memory.
import { createRequire } from 'node:module';
import { MessageChannel, Worker, receiveMessageOnPort, workerData } from 'node:worker_threads';

const ROLE = 'hdtp-identity wasm-memory';
const TIMEOUT_MS = 120_000;

if (workerData && workerData.role === ROLE) {
  const { port, flag } = workerData;
  const Instance = WebAssembly.Instance;
  const built = [];
  let mod, broken;
  WebAssembly.Instance = function (module, imports) {
    const instance = new Instance(module, imports);
    built.push(instance);
    return instance;
  };
  try {
    mod = createRequire(import.meta.url)('./pkg-node/hdtp_identity_wasm.js');
    if (built.length !== 1) broken = `loading the glue built ${built.length} Wasm instances, not one`;
  } catch (e) {
    broken = String(e && e.stack ? e.stack : e);
  } finally {
    WebAssembly.Instance = Instance;
  }
  port.on('message', (request) => {
    let reply;
    try {
      if (broken) throw new Error(broken);
      reply = request.name === undefined ? { bytes: built[0].exports.memory.buffer.byteLength } : { answer: mod.call(request.name, request.args) };
    } catch (e) {
      reply = { failed: String(e && e.stack ? e.stack : e) };
    }
    port.postMessage(reply);
    Atomics.store(flag, 0, 1);
    Atomics.notify(flag, 0);
  });
}

export function fresh() {
  const { port1, port2 } = new MessageChannel();
  const flag = new Int32Array(new SharedArrayBuffer(4));
  const worker = new Worker(new URL(import.meta.url), { workerData: { role: ROLE, port: port2, flag }, transferList: [port2], execArgv: [] });
  worker.unref();
  let closed = false;
  const ask = (request) => {
    if (closed) throw new Error('this instance is closed');
    Atomics.store(flag, 0, 0);
    port1.postMessage(request);
    if (Atomics.wait(flag, 0, 0, TIMEOUT_MS) === 'timed-out') throw new Error(`the Wasm worker did not answer within ${TIMEOUT_MS} ms`);
    const reply = receiveMessageOnPort(port1).message;
    if (reply.failed) throw new Error(reply.failed);
    return reply;
  };
  return {
    call: (name, args) => JSON.parse(ask({ name, args: JSON.stringify(args === undefined ? {} : args) }).answer),
    /** The instance's linear memory, in bytes. It only ever grows. */
    bytes: () => ask({}).bytes,
    /** Ends the instance's worker, and with it the instance. */
    close: () => {
      closed = true;
      port1.close();
      return worker.terminate();
    },
  };
}
