<!-- What changed and why. A change to what an implementation must do needs an accepted SEP in hdtp-spec first (its seps/README.md); a change to the contract starts in contract/contract.json, in both ports. -->

**Contract functions added, changed or removed:** <!-- each by name, or none -->

**MUST entries touched (`js/musts.json`):** <!-- each by section, or none -->

- [ ] Every commit carries `Signed-off-by` (`git commit -s`; the DCO, `CONTRIBUTING.md`).
- [ ] `CHANGELOG.md` has its line under `## Unreleased`.
- [ ] A change to a build input (`js/inputs.mjs`) was committed, then pinned (`sh js/reproduce.sh --pin`), and `js/manifest.json` committed after it.
- [ ] `sh gate.sh` passes, or the pull request says which steps ran (`CONTRIBUTING.md`, "Gates and where they run").
