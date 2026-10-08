# hdtp-identity's release targets. The recipes are scripts (scripts/*.sh), so they fail the way a
# script fails; macOS make is 3.81 and ignores .SHELLFLAGS, so nothing here relies on it.
#
#   make release VERSION=X.Y.Z          cut it locally: gate, version commit, pin, tags, dist/X.Y.Z/
#   make publish VERSION=X.Y.Z          push the branch and both tags, create the GitHub release
#   make verify-release VERSION=X.Y.Z   download a published release and check it, down to a fresh build
#
# Nothing leaves the machine before `make publish`. The gate is `sh gate.sh`.
.PHONY: release publish verify-release

release:
	sh scripts/release.sh "$(VERSION)"

publish:
	sh scripts/publish.sh "$(VERSION)"

# A tag missing locally is fetched from origin by the script, over the remote's own URL.
verify-release:
	sh scripts/verify-release.sh "$(VERSION)"
