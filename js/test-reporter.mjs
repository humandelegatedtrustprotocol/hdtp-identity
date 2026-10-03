// A `node --test` reporter that writes the suite's result file (js/results.mjs's schema): one case per
// top-level test, `<file>: <test name>`, PASS / FAIL / SKIPPED with the failure's message and the
// test's own duration. gate.sh runs it beside the spec reporter:
//
//   HDTP_SUITE=js-tests node --test --test-reporter=spec --test-reporter-destination=stdout \
//     --test-reporter=./js/test-reporter.mjs --test-reporter-destination="$HDTP_RESULTS/js-tests.json" …
import { relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));

export default async function* reporter(source) {
  const cases = [];
  for await (const { type, data } of source) {
    if ((type !== 'test:pass' && type !== 'test:fail') || data.nesting !== 0 || data.details?.type === 'suite') continue;
    const where = data.file ? relative(root, data.file) : '';
    const verdict = data.skip !== undefined || data.todo !== undefined ? 'SKIPPED' : type === 'test:pass' ? 'PASS' : 'FAIL';
    const error = data.details?.error;
    const reason = verdict === 'SKIPPED' ? String(data.skip ?? data.todo ?? 'skipped') : verdict === 'FAIL' ? String(error?.cause?.message ?? error?.message ?? 'failed').split('\n')[0] : null;
    cases.push({ id: where ? `${where}: ${data.name}` : data.name, verdict, reason, ms: Math.round(data.details?.duration_ms ?? 0) });
  }
  yield JSON.stringify({ run: process.env.HDTP_RUN ?? new Date().toISOString(), repo: 'hdtp-identity', tier: process.env.HDTP_TIER ?? 'pre-push', suite: process.env.HDTP_SUITE ?? 'node-test', cases }, null, 1) + '\n';
}
