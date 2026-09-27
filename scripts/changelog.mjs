// CHANGELOG.md and a release. Entries are written under `## Unreleased` as work lands; a release
// moves them under `## X.Y.Z — YYYY-MM-DD` and leaves an empty `## Unreleased` above it.
//
//   node scripts/changelog.mjs --release X.Y.Z YYYY-MM-DD   rewrite CHANGELOG.md; refuses an empty Unreleased
//   node scripts/changelog.mjs --notes X.Y.Z                print that version's section (the release notes)
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const file = fileURLToPath(new URL('../CHANGELOG.md', import.meta.url));
const UNRELEASED = '## Unreleased';

/** The body under the `## <title>` heading, up to the next `## ` heading, or null. */
export function section(text, title) {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => l === `## ${title}` || l.startsWith(`## ${title} `));
  if (start < 0) return null;
  let end = lines.findIndex((l, i) => i > start && l.startsWith('## '));
  if (end < 0) end = lines.length;
  return lines.slice(start + 1, end).join('\n').trim();
}

export function release(text, version, date) {
  const body = section(text, 'Unreleased');
  if (body === null) throw new Error(`CHANGELOG.md has no "${UNRELEASED}" section`);
  if (!body) throw new Error(`CHANGELOG.md's "${UNRELEASED}" section is empty: say what ${version} changes first`);
  if (section(text, version) !== null) throw new Error(`CHANGELOG.md already has a section for ${version}`);
  const lines = text.split('\n');
  const at = lines.indexOf(UNRELEASED);
  lines.splice(at, 1, UNRELEASED, '', `## ${version} — ${date}`);
  return lines.join('\n');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [mode, version, date] = process.argv.slice(2);
  try {
    const text = readFileSync(file, 'utf8');
    if (mode === '--release') {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date ?? '')) throw new Error('usage: --release X.Y.Z YYYY-MM-DD');
      writeFileSync(file, release(text, version, date));
    } else if (mode === '--notes') {
      const body = section(text, version);
      if (!body) throw new Error(`CHANGELOG.md has no section for ${version}`);
      console.log(body);
    } else {
      throw new Error('usage: --release X.Y.Z YYYY-MM-DD | --notes X.Y.Z');
    }
  } catch (e) {
    console.error(`changelog: ${e.message}`);
    process.exit(1);
  }
}
