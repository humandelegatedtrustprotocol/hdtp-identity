// The parity cases, collected: one file per section of contract/contract.json, plus the dispatcher's.
//
// A case is `add(id, fn, args, how)`: its id is its name, unique across every file, and it names the
// function it calls — which must be a function of its file's section, so the files ARE the contract's
// sections. `expect(id, want)` holds a case to what the SPEC says the answer is, for a rule both ports
// could break alike. An `expect` naming an id no case has is a problem, not a quiet no-op: that is how
// a renamed case used to drop its spec check without a sound.
//
// `build` has no file: its one function, `version`, answers what the port IS, which two ports cannot
// agree on.
export const CASE_FILES = ['dispatcher', 'keys', 'certificates', 'csr', 'cards', 'envelopes', 'vault', 'ledger'];
const NO_CASES = ['build'];

const load = (file) => import(`./${file}.mjs`);

/**
 * Every case and expectation, and every problem with the collection itself — each of which fails the
 * run, filtered or not.
 */
export async function collect(f, contract, { files = CASE_FILES, importer = load } = {}) {
  const cases = [], expected = new Map(), problems = [];
  const ids = new Set();
  for (const file of files) {
    const add = (id, fn, args, how = '*') => {
      if (typeof id !== 'string' || !id) problems.push(`cases/${file}.mjs: a case has no id`);
      if (ids.has(id)) problems.push(`the case id ${JSON.stringify(id)} is used twice (again in cases/${file}.mjs)`);
      ids.add(id);
      const section = contract.methods[fn]?.section;
      const isObject = args !== null && typeof args === 'object' && !Array.isArray(args);
      // The dispatcher's cases never reach a function: an unknown name, or arguments that are no object.
      const misfiled = file === 'dispatcher' ? section !== undefined && isObject : section !== file;
      if (misfiled) problems.push(`cases/${file}.mjs: ${JSON.stringify(id)} calls ${fn}, whose section is ${section ?? 'none (not in the contract)'}`);
      cases.push({ id, fn, args, how, file });
    };
    const expect = (id, want) => {
      if (expected.has(id)) problems.push(`cases/${file}.mjs: the answer to ${JSON.stringify(id)} is expected twice`);
      expected.set(id, { want, file });
    };
    (await importer(file)).default({ add, expect }, f);
  }
  for (const [id, { file }] of expected) {
    if (!ids.has(id)) problems.push(`cases/${file}.mjs expects an answer for ${JSON.stringify(id)}, and no case has that id`);
  }
  for (const section of Object.keys(contract.sections)) {
    if (!files.includes(section) && !NO_CASES.includes(section)) problems.push(`the contract's section ${section} has no case file (js/cases/${section}.mjs)`);
  }
  return { cases, expected, problems };
}
