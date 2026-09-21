// Reading `contract.json`, and judging one answer by it.
//
// The contract declares, per function, `params`, `result` and the `errors` it can fail with. This
// is what turns each of those from prose into something a run can contradict:
//
//   result   every answer that is not a failure validates against it, members it does not describe
//            included (`additionalProperties: false` throughout), so a member a port grows is caught
//            the day it appears and one it drops the day it goes;
//   failure  every failure is `{error, why}` and nothing else, with a code the function DECLARES;
//   params   an ACCEPTED call is a described call: when a port did not fail, the arguments it was
//            given validate. One direction only, and said so — nothing here proves that every call
//            the schema admits is accepted, because the cases that would show it are refusals by
//            design, and a refusal's arguments are wrong on purpose. Members whose value is `null`
//            or `undefined` are dropped before validating, because §0 says the JSON literal `null`
//            counts as ABSENT: `{"root_spkis": null}` is "no roots", not a list that is not a list,
//            and a case written as `{ ...args, now: undefined }` is a case with no `now`.
//
// A failure is recognised by its SHAPE — a string `error` beside a `why` — and not by the presence
// of `error` alone: `profile_error` answers `{"error": null | "<words>"}` as its result.
import { readFile } from 'node:fs/promises';
import { compile, validate } from './schema.mjs';

export async function loadContract(url = new URL('./contract.json', import.meta.url)) {
  const contract = JSON.parse(await readFile(url, 'utf8'));
  const root = { $defs: contract.$defs };
  compile(root);
  compile(contract.failure, root, '#/failure');
  const codes = new Set(contract.$defs.ErrorCode.enum);
  for (const [name, m] of Object.entries(contract.methods)) {
    if (!(m.section in contract.sections)) throw new Error(`${name}: section ${JSON.stringify(m.section)} is not one the contract lists`);
    compile(m.params, root, `#/methods/${name}/params`);
    compile(m.result, root, `#/methods/${name}/result`);
    for (const code of m.errors) if (!codes.has(code)) throw new Error(`${name}: declares the error ${JSON.stringify(code)}, which is not an ErrorCode`);
  }
  return { ...contract, root };
}

/** §0: an absent member and a `null` one are the same thing, at every depth. */
const withoutAbsent = (v) => {
  if (Array.isArray(v)) return v.map(withoutAbsent);
  if (!v || typeof v !== 'object') return v;
  return Object.fromEntries(
    Object.entries(v).filter(([, x]) => x !== null && x !== undefined).map(([k, x]) => [k, withoutAbsent(x)]),
  );
};

export const isFailure = (answer) =>
  !!answer && typeof answer === 'object' && !Array.isArray(answer) && typeof answer.error === 'string' && 'why' in answer;

/**
 * What is wrong with `answer`, as the contract sees it; `[]` when nothing is. `seen`, when given,
 * collects the error codes each function was observed to fail with, so a run can also say which
 * DECLARED codes it never saw.
 */
export function judge(contract, fn, args, answer, seen) {
  const m = contract.methods[fn];
  if (isFailure(answer)) {
    const wrong = validate(contract.failure, answer, contract.root).map((w) => `failure ${w}`);
    if (m) {
      if (seen) seen.set(fn, (seen.get(fn) ?? new Set()).add(answer.error));
      if (!m.errors.includes(answer.error)) wrong.push(`fails with ${JSON.stringify(answer.error)} (${JSON.stringify(answer.why)}), which the contract does not declare for it`);
    } else if (answer.error !== 'unsupported') {
      wrong.push(`a name the contract does not have answered ${JSON.stringify(answer.error)}, not "unsupported"`);
    }
    return wrong;
  }
  if (!m) return [`a name the contract does not have was answered: ${JSON.stringify(answer).slice(0, 120)}`];
  return [
    ...validate(m.result, answer, contract.root).map((w) => `result ${w}`),
    ...validate(m.params, withoutAbsent(args), contract.root).map((w) => `accepted, yet params ${w}`),
  ];
}
