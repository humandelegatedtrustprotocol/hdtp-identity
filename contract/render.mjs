// `CONTRACT.md` is GENERATED from `contract.json`. This is what generates it.
//
//   node contract/render.mjs            write ../CONTRACT.md
//   node contract/render.mjs --check    fail if what is committed is not what this would write
//
// The document has two kinds of content and they live in two places. Its PROSE — §0's conventions,
// §5.1's order of the receiving rules, §6's vault format, §7's list of gates — is
// `contract/CONTRACT.template.md`, hand-written, because none of it is per-function. Its TABLES are
// rendered here from the contract file, one row per function, so that the boundary's shape is
// stated once: a member added to an answer, a defaulted argument, a new error code, a function that
// arrives or leaves. Before this, the tables were prose beside the code and drifted from it —
// `card_decode` lost its `leaf` member in one port, and `decide` answered with a `tool` in one and
// without it in the other, both with the tables reading as though nothing had happened.
//
// The same file is what `js/parity.mjs` validates every answer of both ports against, so the tables
// below and the gate cannot describe different contracts.
import { readFile, writeFile } from 'node:fs/promises';
import { loadContract } from './contract.mjs';
import { resolve } from './schema.mjs';

const OUT = new URL('../CONTRACT.md', import.meta.url);
const TEMPLATE = new URL('./CONTRACT.template.md', import.meta.url);

/** A schema as a short type word: the `$defs` name where there is one, else what it constrains. */
function typeWord(s, root) {
  if (s === true) return 'any';
  if (s.$ref) return s.$ref.replace('#/$defs/', '');
  if (s.enum) return s.enum.map((v) => (typeof v === 'string' ? v : JSON.stringify(v))).join('\\|');
  if ('const' in s) return JSON.stringify(s.const);
  if (s.oneOf) return s.oneOf.map((x) => typeWord(x, root)).join(' \\| ');
  if (s.anyOf) return s.anyOf.map((x) => typeWord(x, root)).join(' \\| ');
  if (Array.isArray(s.type)) return s.type.join('\\|');
  if (s.type === 'array') return s.items ? `[${typeWord(s.items, root)}]` : 'array';
  if (s.type === 'object') return members(s, root);
  return s.type ?? 'any';
}

/** `{"a", "b"?}` — the members of an object schema, optional ones marked, in the schema's order. */
function members(s, root) {
  const resolved = s.$ref ? resolve(s.$ref, root) : s;
  // An object that declares no members is `{…}` — said here, not by asking `typeWord`, which would
  // ask back (it renders an object through this function) until the stack ran out.
  if (!resolved.properties) return resolved.type === 'object' || typeWord(resolved, root) === 'any' ? '`{…}`' : typeWord(resolved, root);
  const req = new Set(resolved.required ?? []);
  const parts = Object.entries(resolved.properties).map(([name, sub]) => {
    const word = typeWord(sub, root);
    return `\`${name}\`${req.has(name) ? '' : '?'}${word === 'any' ? '' : `: ${word}`}`;
  });
  return parts.length ? parts.join(', ') : '—';
}

/** One row: the name, what it takes, what it answers, and the notes the contract carries. */
function row(name, m, root) {
  const out = m.result.oneOf
    ? m.result.oneOf.map((alt) => members(alt, root)).join('<br>or ')
    : members(m.result, root);
  const notes = (m.notes ?? '').replace(/\n/g, ' ').trim();
  // The error codes belong in the table, not only in the file: a caller's switch is written from
  // this, and `js/parity.mjs` fails a port that answers with a code the row does not carry.
  const fails = m.errors.length ? `<br>*fails:* ${m.errors.map((c) => `\`${c}\``).join(', ')}` : '<br>*never fails*';
  return `| \`${name}\` | ${members(m.params, root)} | ${out}${fails} | ${notes} |`;
}

function table(contract, section) {
  const rows = Object.entries(contract.methods).filter(([, m]) => m.section === section);
  if (!rows.length) throw new Error(`no function is in section ${JSON.stringify(section)}`);
  return [
    '| Function | Input | Output | Notes |',
    '|---|---|---|---|',
    ...rows.map(([name, m]) => row(name, m, contract.root)),
  ].join('\n');
}

/** The appendix: every domain type the tables name, so the document explains its own words. */
function types(contract) {
  const rows = Object.entries(contract.$defs).map(([name, s]) => {
    const shape = s.properties
      ? members(s, contract.root)
      : s.oneOf
        ? s.oneOf.map((alt) => members(alt, contract.root)).join('<br>or ')
        : typeWord(s, contract.root);
    return `| \`${name}\` | ${shape} | ${(s.description ?? '').replace(/\n/g, ' ').trim()} |`;
  });
  return ['| Type | Shape | |', '|---|---|---|', ...rows].join('\n');
}

export async function render() {
  const contract = await loadContract();
  const template = await readFile(TEMPLATE, 'utf8');
  const wanted = new Set(Object.keys(contract.sections));
  let text = template.replace(/^\{\{table:([a-z]+)\}\}$/gm, (_, section) => {
    if (!wanted.delete(section)) throw new Error(`the template asks for a table of ${JSON.stringify(section)}, which the contract does not list as a section`);
    return table(contract, section);
  });
  if (wanted.size) throw new Error(`the template has no table for: ${[...wanted].join(', ')} — every section the contract declares is rendered somewhere, or its functions are invisible`);
  text = text.replace(/^\{\{types\}\}$/m, () => types(contract));
  const filled = text
    .replaceAll('{{spec}}', contract.spec)
    .replaceAll('{{count}}', String(Object.keys(contract.methods).length))
    // §0's list of failure codes, from the enum itself: written by hand, it named four codes no port
    // emits and the enum does not have (R35).
    .replaceAll('{{error_codes}}', contract.$defs.ErrorCode.enum.map((c) => `\`${c}\``).join(', '));
  if (/\{\{/.test(filled)) throw new Error(`a placeholder was left unrendered: ${filled.match(/\{\{[^}]*\}\}/)[0]}`);
  return filled;
}

const text = await render();
if (process.argv.includes('--check')) {
  const have = await readFile(OUT, 'utf8').catch(() => '');
  if (have !== text) {
    console.error('CONTRACT.md is not what contract/contract.json and CONTRACT.template.md render.');
    console.error('Run `node contract/render.mjs` and commit the result.');
    process.exit(1);
  }
  console.log(`CONTRACT.md is current (${Object.keys((await loadContract()).methods).length} functions)`);
} else {
  await writeFile(OUT, text);
  console.log(`CONTRACT.md written (${Object.keys((await loadContract()).methods).length} functions)`);
}
