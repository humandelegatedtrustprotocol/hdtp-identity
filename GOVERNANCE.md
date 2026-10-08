# Governance

hdtp-identity has one maintainer. This file is how decisions about the library are made today, and
what changes when more people take part.

## Who decides

The maintainers listed in `MAINTAINERS.md` decide what the library does. There is one, Sumit
Agrawal, for Shailka Systems Private Limited, and so one decision-maker: a change lands when he
merges it. There is no steering committee, working group or foundation, and none is implied by
anything in this repository.

What the library must do is decided elsewhere: the protocol is hdtp-spec's, and a change to what an
implementation must do is an enhancement proposal there (its `seps/README.md`) before it is code
here. A decision about this repository — the contract, a port, the build, a release — is made in
the open where it can be, in a pull request or an issue.

## How the library changes

- **The contract.** `contract/contract.json` is the boundary every port presents: a function name
  and JSON arguments in, JSON out. `CONTRACT.md` is rendered from it (`node contract/render.mjs`),
  and `js/parity.mjs` validates every answer of both ports against it on every gate run. A member
  added to an answer, a defaulted argument, a new error code, a function that arrives or leaves is
  a change to that file first, in both ports in the same change. hdtp-spec's committed JSON Schema
  is generated from it (`schema/gen.mjs` there), and the gate here fails until that schema is
  regenerated, as a spec pull request.
- **Versions.** One semver version for the Rust crates, the Go module and the Wasm package, written
  in seven places and held equal by `node scripts/version.mjs --check`. Before 1.0.0 a minor version
  may change the contract. `CHANGELOG.md` records what each release changed; entries go under
  `## Unreleased` as they land, and a release dates them.
- **Releases** are cut by a maintainer, locally, and nothing leaves the machine before the second
  step:
  - `make release VERSION=X.Y.Z` refuses a tree that is not clean and on `main`, a version not above
    the last tag or already tagged, an empty `## Unreleased`, and an hdtp-spec checkout with
    uncommitted changes; then it runs the gate, writes the version into every copy, dates the
    changelog section, commits, pins the Wasm of that commit in the container build
    (`sh js/reproduce.sh --pin`), commits `js/manifest.json`, tags the commit `vX.Y.Z` and
    `go/vX.Y.Z`, and packs `dist/X.Y.Z/`;
  - `make publish VERSION=X.Y.Z` pushes `main` and both tags with a plain `git push`, through the
    pre-push hook, and creates the GitHub release with every asset and the changelog section as its
    notes;
  - `make verify-release VERSION=X.Y.Z` downloads a published release and checks it against its
    sums and manifest, against the pin at its tag, and against a fresh container build of that tag.
- **Evidence.** The code is held by gates, all run locally; nothing runs on GitHub
  (`CONTRIBUTING.md`, "Gates and where they run"). The pre-commit hook styles and lints the Rust;
  the pre-push hook runs `sh gate.sh`: the Rust core, the CLI and the Wasm crate's tests, the Go
  port's, the pin of this commit, Appendix B and hdtp-spec's intrusion scenarios through both
  ports, the contract's validator and `CONTRACT.md`, hdtp-spec's schema against this contract, the
  parity of the two ports, the name guard, and the MUST registry — every normative sentence of the
  specification naming the test or scenario that holds it. A change the gates cannot hold says so
  in its pull request.

## Licence

Everything in this repository is Apache-2.0 (`LICENSE`, with `NOTICE`), except
`CODE_OF_CONDUCT.md`, the Contributor Covenant 2.1 by its authors under CC BY 4.0. A contribution is
accepted only under those terms (`CONTRIBUTING.md`).

## When more people take part

Maintainers are added by the existing maintainers, by a change to `MAINTAINERS.md` that says what
each new maintainer is responsible for. If the project gains maintainers from outside Shailka
Systems Private Limited, this file will be rewritten to say how they decide together, before that
change is merged.

## Conduct

`CODE_OF_CONDUCT.md`, the Contributor Covenant 2.1, applies in every space of the project.
