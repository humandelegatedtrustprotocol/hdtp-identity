// The worker thread behind the Go port (js/port.mjs): it keeps ONE `pact-identity-go` process for the
// whole suite and relays line-delimited JSON to it. The caller blocks on `signal` (Atomics) and takes
// the answer with `receiveMessageOnPort`, so `port.call` stays synchronous, as the Wasm port's is.
//
// A process that dies takes only the calls it was holding: each is answered `{ threw }`, and the next
// call starts a new process. That is the isolation the old one-process-per-call mode gave for free.
import { workerData, parentPort } from 'node:worker_threads';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

const { bin, port, signal } = workerData;
let child = null;

function reply(id, body) {
  port.postMessage({ id, ...body });
  Atomics.add(signal, 0, 1);
  Atomics.notify(signal, 0);
}

function start() {
  const me = spawn(bin, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  const waiting = []; // ids in the order their requests were written; answers come back in that order
  let stderr = '';
  me.stderr.on('data', (d) => { stderr += d; });
  me.stdin.on('error', () => {}); // a write to a process that died is answered by 'close' below
  createInterface({ input: me.stdout, crlfDelay: Infinity }).on('line', (line) => {
    const id = waiting.shift();
    if (id !== undefined) reply(id, { line, pid: me.pid });
  });
  // Once it has exited nothing new is written to it; what it was still holding is failed when its
  // output has been read to the end, so an answer it wrote before dying still reaches its caller.
  const retire = () => { if (child?.proc === me) child = null; };
  const died = (why) => {
    retire();
    for (const id of waiting.splice(0)) reply(id, { threw: `pact-identity-go ${why}${stderr ? `: ${stderr.slice(0, 500)}` : ''}` });
  };
  me.on('exit', retire);
  me.on('error', (e) => died(`could not run: ${e.message}`));
  me.on('close', (code, sig) => died(`exited ${code ?? sig}`));
  return { proc: me, waiting };
}

parentPort.on('message', ({ id, line, kill }) => {
  // The caller gave up on a call: this process is abandoned now, not when it gets round to dying, and
  // the next call goes to a new one.
  if (kill) { const hung = child; child = null; hung?.proc.kill('SIGKILL'); return; }
  child ??= start();
  child.waiting.push(id);
  child.proc.stdin.write(line + '\n');
});
