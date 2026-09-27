// The release recipe (make release / make publish / make verify-release), run for real against
// stubs: a copy of this repository in a scratch directory, a bare repository as its origin, a stub
// gate, a stub pin that writes fake Wasm packages and then runs the REAL js/manifest.mjs, a stub CLI
// build and a stub gh. Nothing here builds, pushes to a real remote or talks to GitHub.
//
// What must hold: every refusal refuses before anything is committed; a release makes exactly two
// commits and two tags on one commit, writes the version into every copy, and packs exactly the
// assets the format names, with nothing reaching origin; publish pushes the branch and both tags
// and hands gh every asset; verify-release passes that release and fails a tampered one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, chmodSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../', import.meta.url));
const sha = (b) => createHash('sha256').update(b).digest('hex');

// The child sees none of the caller's git, make or release state: a gate run from a hook carries
// GIT_DIR, and `make release` carries MAKEFLAGS (and its VERSION) into every make below it.
function cleanEnv(extra) {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (!/^(GIT_|MAKE|MFLAGS$|RELEASE_|GH$|GH_SOURCE$|PROTOCOL_DIR$|VERSION$)/.test(k)) env[k] = v;
  }
  return { ...env, ...extra };
}

function fixture({ branch = 'main' } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'pact-release-'));
  const work = join(root, 'work'), bin = join(root, 'bin'), log = join(root, 'log');
  mkdirSync(work); mkdirSync(bin); writeFileSync(log, ''); writeFileSync(join(root, 'gitconfig'), '');
  const env = cleanEnv({ GIT_CONFIG_GLOBAL: join(root, 'gitconfig'), GIT_CONFIG_NOSYSTEM: '1' });
  const git = (cwd, ...args) => execFileSync('git', args, { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  // This tree's TRACKED regular files, as they are on disk (so an uncommitted edit to a recipe is
  // what runs). Not untracked ones: a checkout can hold anything untracked — a nested worktree, a
  // symlink to a sibling — and copying those made every test here fail in the main checkout, whose
  // .claude/ holds exactly that.
  const files = execFileSync('git', ['ls-files', '-z'], { cwd: repo, encoding: 'utf8' }).split('\0').filter(Boolean);
  for (const f of files) {
    if (!existsSync(join(repo, f)) || !lstatSync(join(repo, f)).isFile()) continue;
    mkdirSync(dirname(join(work, f)), { recursive: true });
    cpSync(join(repo, f), join(work, f));
  }
  // The fixture's own release state, not this tree's: after a real release this tree is AT its
  // version with an empty Unreleased section, and a fixture copied as it stands could never release
  // again — the test went red on the very commit it was released from.
  execFileSync('node', ['scripts/version.mjs', '--set', '0.1.0'], { cwd: work, stdio: 'ignore' });
  writeFileSync(join(work, 'CHANGELOG.md'), '# Changelog\n\n## Unreleased\n\n- a change the fixture releases\n\n## 0.1.0 — 2026-01-01\n\n- before\n');
  git(work, 'init', '-q', '-b', branch);
  for (const [k, v] of [['user.name', 'release test'], ['user.email', 'release@test.invalid'], ['commit.gpgsign', 'false'], ['tag.gpgsign', 'false']]) git(work, 'config', k, v);
  git(work, 'add', '-A'); git(work, 'commit', '-q', '-m', 'fixture');
  git(root, 'init', '-q', '--bare', 'origin.git');
  git(work, 'remote', 'add', 'origin', join(root, 'origin.git'));
  const protocol = join(root, 'protocol');
  mkdirSync(protocol); writeFileSync(join(protocol, 'SPEC.md'), 'spec\n');
  git(protocol, 'init', '-q');
  for (const [k, v] of [['user.name', 't'], ['user.email', 't@test.invalid']]) git(protocol, 'config', k, v);
  git(protocol, 'add', '-A'); git(protocol, 'commit', '-q', '-m', 'protocol');

  // The pin stub: fake packages, then the real manifest writer over them.
  writeFileSync(join(bin, 'pin.sh'), `#!/bin/sh
set -eu
echo pin >> "${log}"
v="$(node scripts/version.mjs)"
for p in pkg-web pkg-node; do
  mkdir -p "js/$p"
  printf '*' > "js/$p/.gitignore"; printf '{"name":"x"}' > "js/$p/package.json"
  printf 'glue %s %s' "$p" "$v" > "js/$p/pact_identity_wasm.js"; printf 'wasm %s' "$v" > "js/$p/pact_identity_wasm_bg.wasm"
  printf 'd.ts' > "js/$p/pact_identity_wasm.d.ts"; printf 'bg d.ts' > "js/$p/pact_identity_wasm_bg.wasm.d.ts"
done
printf '{"rustc":"rustc stub","wasm_pack":"wasm-pack stub"}' > "${join(root, 'toolchain.json')}"
node js/manifest.mjs "${join(root, 'toolchain.json')}" >/dev/null
`);
  writeFileSync(join(bin, 'cli.sh'), `#!/bin/sh
set -eu
tag="$1"; out="$2"; v="$3"; shift 3
echo "cli $tag $*" >> "${log}"
for t in "$@"; do printf 'pact %s %s' "$v" "$t" > "$out/pact-$v-$t"; done
`);
  // The gh stub: records every call; \`release download <tag> --dir <d>\` copies from $GH_SOURCE.
  writeFileSync(join(bin, 'gh'), `#!/bin/sh
echo "gh $*" >> "${log}"
if [ "$1 $2" = "release download" ]; then cp "$GH_SOURCE"/* "$5"/; fi
`);
  for (const f of ['pin.sh', 'cli.sh', 'gh']) chmodSync(join(bin, f), 0o755);

  const stubs = {
    RELEASE_GATE: `echo gate >> "${log}"`,
    RELEASE_PIN: `sh "${join(bin, 'pin.sh')}"`,
    RELEASE_LOCKCHECK: 'true',
    RELEASE_CLI: `sh "${join(bin, 'cli.sh')}"`,
    PROTOCOL_DIR: protocol,
    RELEASE_DATE: '2026-09-27',
    GH: join(bin, 'gh'),
  };
  const make = (target, version, extra = {}) => spawnSync('make', ['-s', target, `VERSION=${version}`], { cwd: work, env: { ...env, ...stubs, ...extra }, encoding: 'utf8' });
  const cleanup = () => rmSync(root, { recursive: true, force: true });
  return { root, work, log, protocol, git: (...a) => git(work, ...a), gitIn: git, make, cleanup, calls: () => readFileSync(log, 'utf8') };
}

function refused(f, version, pattern) {
  const [head, tags, status] = [f.git('rev-parse', 'HEAD'), f.git('tag', '-l'), f.git('status', '--porcelain')];
  const r = f.make('release', version);
  assert.notEqual(r.status, 0, `expected a refusal, got success:\n${r.stdout}`);
  assert.match(r.stderr, pattern);
  assert.equal(f.git('rev-parse', 'HEAD'), head, 'a refusal committed something');
  assert.equal(f.git('tag', '-l'), tags, 'a refusal tagged something');
  assert.equal(f.git('status', '--porcelain'), status, 'a refusal changed a file');
  assert.doesNotMatch(f.calls(), /gate|pin|cli/, 'a refusal ran a step');
}

test('refuses a VERSION that is not X.Y.Z', () => {
  const f = fixture();
  try {
    for (const v of ['', '0.2', 'v0.2.0', '0.2.0-rc1', '01.2.0']) refused(f, v, /VERSION must be X\.Y\.Z/);
  } finally { f.cleanup(); }
});

test('refuses a branch other than main, unless RELEASE_BRANCH names it', () => {
  const f = fixture({ branch: 'feature' });
  try {
    refused(f, '0.2.0', /on branch feature; a release is cut from main/);
    const r = f.make('release', '0.2.0', { RELEASE_BRANCH: 'feature' });
    assert.equal(r.status, 0, r.stderr);
  } finally { f.cleanup(); }
});

test('refuses a dirty tree: a modified file, and an untracked one', () => {
  const f = fixture();
  try {
    appendFileSync(join(f.work, 'README.md'), 'x\n');
    refused(f, '0.2.0', /the tree is not clean/);
    f.git('restore', 'README.md');
    writeFileSync(join(f.work, 'stray.txt'), 'x');
    refused(f, '0.2.0', /the tree is not clean/);
  } finally { f.cleanup(); }
});

test('refuses a version not above the last vX.Y.Z tag, or already tagged; go/ tags do not count', () => {
  const f = fixture();
  try {
    // Two tags, so the last release has to be chosen numerically: v0.9.0 sorts after v0.10.0 as text.
    f.git('tag', 'v0.9.0'); f.git('tag', 'v0.10.0');
    const chk = (v, re) => {
      const r = f.make('release', v);
      assert.notEqual(r.status, 0, `${v} was not refused`);
      assert.match(r.stderr, re);
      assert.equal(f.git('tag', '-l'), 'v0.10.0\nv0.9.0');
      assert.equal(f.git('log', '--format=%s'), 'fixture');
    };
    chk('0.10.0', /tag v0\.10\.0 already exists/);
    chk('0.9.9', /not above the last release, v0\.10\.0/); // numeric, not lexical: 0.9.9 < 0.10.0
    chk('0.2.0', /not above the last release, v0\.10\.0/);
    f.git('tag', '-d', 'v0.10.0', 'v0.9.0');
    f.git('tag', 'go/v9.9.9');
    const r = f.make('release', '0.2.0');
    assert.equal(r.status, 0, `a go/ tag blocked the release:\n${r.stderr}`);
  } finally { f.cleanup(); }
});

test('refuses an empty Unreleased section, and a dirty protocol checkout', () => {
  const f = fixture();
  try {
    const cl = join(f.work, 'CHANGELOG.md');
    const text = readFileSync(cl, 'utf8');
    writeFileSync(cl, text.replace(/## Unreleased\n[\s\S]*$/, '## Unreleased\n'));
    f.git('commit', '-q', '-am', 'fixture');
    refused(f, '0.2.0', /Unreleased' section is empty/);
    writeFileSync(cl, text); f.git('commit', '-q', '-am', 'fixture');
    writeFileSync(join(f.protocol, 'SPEC.md'), 'edited\n');
    refused(f, '0.2.0', /has uncommitted changes/);
  } finally { f.cleanup(); }
});

test('a release: two commits, two tags on the second, the version everywhere, exactly the assets, nothing pushed', () => {
  const f = fixture();
  try {
    const r = f.make('release', '0.2.0', { RELEASE_COMMIT_TRAILER: 'Trailer: yes' });
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.deepEqual(f.git('log', '--format=%s').split('\n'), ['The pin of 0.2.0', 'Release 0.2.0', 'fixture']);
    assert.match(f.git('log', '-1', '--format=%b'), /Trailer: yes/);
    assert.equal(f.git('status', '--porcelain'), '', 'the release left the tree dirty');
    const head = f.git('rev-parse', 'HEAD');
    assert.equal(f.git('rev-parse', 'v0.2.0^{commit}'), head);
    assert.equal(f.git('rev-parse', 'go/v0.2.0^{commit}'), head);
    assert.equal(f.git('cat-file', '-t', 'v0.2.0'), 'tag', 'tags are annotated');
    // The steps ran in order: gate, then pin, then the CLI from the tag.
    assert.deepEqual(f.calls().trim().split('\n'), ['gate', 'pin', 'cli v0.2.0 darwin-arm64 linux-amd64 linux-arm64']);
    // One version, everywhere; the pin records it; the changelog is dated.
    assert.equal(execFileSync('node', ['scripts/version.mjs', '--check'], { cwd: f.work, encoding: 'utf8' }).trim(), 'version: ok (0.2.0 in all 6 places)');
    const pin = JSON.parse(readFileSync(join(f.work, 'js/manifest.json'), 'utf8'));
    assert.equal(pin.crate_version, '0.2.0');
    assert.match(readFileSync(join(f.work, 'CHANGELOG.md'), 'utf8'), /## Unreleased\n\n## 0\.2\.0 — 2026-09-27\n\n- a change the fixture releases\n/);
    // The assets, and nothing else.
    const dist = join(f.work, 'dist/0.2.0');
    const assets = ['pact-0.2.0-darwin-arm64', 'pact-0.2.0-linux-amd64', 'pact-0.2.0-linux-arm64', 'pact-identity-exportcorpus-0.2.0.tgz', 'pact-identity-wasm-web-0.2.0.tgz'];
    assert.deepEqual(readdirSync(dist).sort(), ['SHA256SUMS', 'manifest.json', ...assets].sort());
    const sums = readFileSync(join(dist, 'SHA256SUMS'), 'utf8').trim().split('\n');
    assert.deepEqual(sums.map((l) => l.split('  ')[1]), ['manifest.json', ...assets].sort());
    for (const l of sums) { const [h, n] = l.split('  '); assert.equal(sha(readFileSync(join(dist, n))), h, n); }
    const m = JSON.parse(readFileSync(join(dist, 'manifest.json'), 'utf8'));
    assert.equal(m.version, '0.2.0');
    assert.equal(m.commit, head);
    assert.deepEqual(m.tags, ['v0.2.0', 'go/v0.2.0']);
    assert.equal(m.protocol_commit, f.gitIn(f.protocol, 'rev-parse', 'HEAD'));
    for (const k of Object.keys(pin)) assert.deepEqual(m[k], pin[k], `manifest.json's ${k} is not the pin's`);
    assert.deepEqual(Object.keys(m.assets).sort(), assets);
    const listing = execFileSync('tar', ['-tzf', join(dist, 'pact-identity-wasm-web-0.2.0.tgz')], { encoding: 'utf8' }).trim().split('\n');
    assert.deepEqual(listing.filter((n) => !n.endsWith('/')).sort(), Object.keys(pin.files).filter((k) => k.startsWith('pkg-web/')).sort());
    assert.ok(listing.every((n) => n.startsWith('pkg-web/')), `the tarball has something outside pkg-web/: ${listing}`);
    // The corpus: cases.json and every zip, under exportcorpus/, and nothing of the generator.
    const corpus = execFileSync('tar', ['-tzf', join(dist, 'pact-identity-exportcorpus-0.2.0.tgz')], { encoding: 'utf8' }).trim().split('\n').filter((n) => !n.endsWith('/')).sort();
    const tracked = readdirSync(join(f.work, 'go/exportcorpus')).filter((n) => n === 'cases.json' || n.endsWith('.zip')).map((n) => `exportcorpus/${n}`).sort();
    assert.ok(tracked.length > 2, 'the fixture has no corpus to pack');
    assert.deepEqual(corpus, tracked);
    assert.ok(!corpus.some((n) => n.endsWith('.go')), `the corpus tarball carries the generator: ${corpus}`);
    assert.match(readFileSync(join(f.work, 'dist/0.2.0-notes.md'), 'utf8'), /^- a change the fixture releases$/m);
    // Nothing left the machine.
    assert.equal(f.gitIn(join(f.root, 'origin.git'), 'for-each-ref'), '', 'the release pushed something');
    assert.doesNotMatch(f.calls(), /^gh /m, 'the release called gh');
    // And the same version cannot be cut twice.
    const again = f.make('release', '0.2.0');
    assert.notEqual(again.status, 0);
    assert.match(again.stderr, /tag v0\.2\.0 already exists/);
  } finally { f.cleanup(); }
});

test('publish pushes the branch and both tags and gives gh every asset; verify-release passes it and fails a tampered copy', () => {
  const f = fixture();
  try {
    assert.equal(f.make('release', '0.2.0').status, 0);
    const r = f.make('publish', '0.2.0');
    assert.equal(r.status, 0, r.stderr);
    const origin = join(f.root, 'origin.git');
    const refs = f.gitIn(origin, 'for-each-ref', '--format=%(refname) %(objectname)').split('\n').sort();
    assert.deepEqual(refs, [
      `refs/heads/main ${f.git('rev-parse', 'HEAD')}`,
      `refs/tags/go/v0.2.0 ${f.git('rev-parse', 'go/v0.2.0')}`,
      `refs/tags/v0.2.0 ${f.git('rev-parse', 'v0.2.0')}`,
    ]);
    const create = f.calls().split('\n').find((l) => l.startsWith('gh release create'));
    assert.ok(create, 'gh release create was not called');
    assert.match(create, /^gh release create v0\.2\.0 --verify-tag --title pact-identity 0\.2\.0 --notes-file dist\/0\.2\.0-notes\.md /);
    for (const n of readdirSync(join(f.work, 'dist/0.2.0'))) assert.ok(create.includes(`dist/0.2.0/${n}`), `gh was not given ${n}`);

    // verify-release, against a stub gh that serves the release as it was cut.
    const served = join(f.root, 'served');
    cpSync(join(f.work, 'dist/0.2.0'), served, { recursive: true });
    const verify = () => f.make('verify-release', '0.2.0', { GH_SOURCE: served, RELEASE_REPRODUCE: `echo reproduce >> "${f.log}"` });
    let v = verify();
    assert.equal(v.status, 0, v.stderr);
    assert.match(f.calls(), /^reproduce$/m, 'verify-release did not run the fresh build');
    // One byte added to the Wasm tarball is caught by SHA256SUMS.
    const tgz = join(served, 'pact-identity-wasm-web-0.2.0.tgz');
    const good = readFileSync(tgz);
    writeFileSync(tgz, Buffer.concat([good, Buffer.from([0])]));
    v = verify();
    assert.notEqual(v.status, 0);
    assert.match(v.stderr, /pact-identity-wasm-web-0\.2\.0\.tgz: its sha256 is not the one SHA256SUMS lists/);
    writeFileSync(tgz, good);
    // A corpus tarball re-packed with one zip changed, its hashes rewritten in SHA256SUMS and the
    // manifest to match, is caught against the tag's go/exportcorpus.
    const corpusTgz = join(served, 'pact-identity-exportcorpus-0.2.0.tgz');
    const goodCorpus = readFileSync(corpusTgz);
    const sumsBefore = readFileSync(join(served, 'SHA256SUMS'), 'utf8'), manifestBefore = readFileSync(join(served, 'manifest.json'), 'utf8');
    const unpacked = mkdtempSync(join(tmpdir(), 'pact-corpus-'));
    execFileSync('tar', ['-xzf', corpusTgz, '-C', unpacked]);
    appendFileSync(join(unpacked, 'exportcorpus/valid-book.zip'), 'x');
    execFileSync('tar', ['-czf', corpusTgz, '-C', unpacked, 'exportcorpus']);
    const forged = readFileSync(corpusTgz);
    const man = JSON.parse(manifestBefore);
    man.assets['pact-identity-exportcorpus-0.2.0.tgz'] = { sha256: sha(forged), bytes: forged.length };
    writeFileSync(join(served, 'manifest.json'), JSON.stringify(man, null, 2) + '\n');
    writeFileSync(join(served, 'SHA256SUMS'), sumsBefore
      .replace(/^[0-9a-f]{64}(?= {2}pact-identity-exportcorpus-0\.2\.0\.tgz$)/m, sha(forged))
      .replace(/^[0-9a-f]{64}(?= {2}manifest\.json$)/m, sha(readFileSync(join(served, 'manifest.json')))));
    v = verify();
    assert.notEqual(v.status, 0);
    assert.match(v.stderr, /pact-identity-exportcorpus-0\.2\.0\.tgz: valid-book\.zip is not the tag's/);
    writeFileSync(corpusTgz, goodCorpus);
    writeFileSync(join(served, 'SHA256SUMS'), sumsBefore);
    writeFileSync(join(served, 'manifest.json'), manifestBefore);
    rmSync(unpacked, { recursive: true, force: true });
    // A replaced CLI whose SHA256SUMS line was rewritten to match is still caught, by manifest.json.
    const cli = join(served, 'pact-0.2.0-linux-arm64');
    writeFileSync(cli, 'tampered');
    const sumsFile = join(served, 'SHA256SUMS');
    writeFileSync(sumsFile, readFileSync(sumsFile, 'utf8').replace(/^[0-9a-f]{64}(?= {2}pact-0\.2\.0-linux-arm64$)/m, sha(Buffer.from('tampered'))));
    v = verify();
    assert.notEqual(v.status, 0);
    assert.match(v.stderr, /pact-0\.2\.0-linux-arm64: 8 bytes, sha256 \S+; manifest\.json says/);
  } finally { f.cleanup(); }
});
