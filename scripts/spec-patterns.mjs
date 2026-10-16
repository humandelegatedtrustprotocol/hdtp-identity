// Two rules over tracked text that this repository and hdtp-spec both hold, read out of hdtp-spec so
// each has one definition: the article before the name, and a path from the machine that wrote it.
//
//   node scripts/spec-patterns.mjs <hdtp-spec> article   the pattern for `git grep -P`
//   node scripts/spec-patterns.mjs <hdtp-spec> local     the pattern for `git grep -E` and `grep -E`
//
// The article is hdtp-spec's exported ARTICLE (vectors/lib/stated.mjs). The local-path pattern is the
// regular-expression literal `const LOCAL = /…/` in scripts/check-local-paths.mjs, read as text: that
// module runs its own check when it is imported. Only `\/` is unescaped; any other backslash would
// mean something else in an extended regular expression, so it is refused rather than passed on.
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const [spec, which] = process.argv.slice(2);
const refuse = (why) => {
  console.error(`spec-patterns: ${why}`);
  process.exit(2);
};
if (!spec || !['article', 'local'].includes(which)) refuse('usage: spec-patterns.mjs <hdtp-spec> article|local');

if (which === 'article') {
  const file = join(resolve(spec), 'vectors/lib/stated.mjs');
  const { ARTICLE } = await import(pathToFileURL(file).href);
  if (!(ARTICLE instanceof RegExp)) refuse(`${file} exports no ARTICLE pattern`);
  process.stdout.write(ARTICLE.source);
} else {
  const file = join(spec, 'scripts/check-local-paths.mjs');
  const m = /^const LOCAL = \/(.+)\/[a-z]*$/m.exec(readFileSync(file, 'utf8'));
  if (!m) refuse(`${file} holds no line 'const LOCAL = /…/'`);
  const ere = m[1].replaceAll('\\/', '/');
  if (ere.includes('\\')) refuse(`${file}'s LOCAL carries a backslash other than \\/, which an extended regular expression reads otherwise: ${m[1]}`);
  process.stdout.write(ere);
}
