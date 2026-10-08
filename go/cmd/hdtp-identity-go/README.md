# hdtp-identity-go

The stdin adapter of the Go port. It reads one JSON request per line, `{"fn": name, "args": {...}}`,
and writes one JSON answer per line, until stdin closes; the answer is `hdtpidentity.Call(fn, args)`,
so it is the contract's boundary over a pipe. The JavaScript harness is its only consumer: a driver
keeps one process open for a whole suite (`js/port.mjs`, through the worker thread of
`js/go-adapter.mjs`), and a single request piped in is the same protocol with one line.

Build: `make build` in `go/` writes `go/bin/hdtp-identity-go` (the directory is git-ignored).
`gate.sh` builds it in its "Go port" step; `js/check.mjs --port go` and the other drivers say so,
and stop, when it is missing.

What it refuses: a line that is not `{"fn", "args"}` is answered
`{"error":"parse","why":"request is not {\"fn\", \"args\"}"}`; a request with no `args` means `{}`;
every other refusal is the library's own, in the contract's codes. The process always exits 0:
every failure is in the JSON.

Held by: the harness suites that drive it (`js/check.mjs --port go`, `js/intrude.mjs --port go`,
`js/parity.mjs`) and `js/port.test.mjs`, which holds that a process that dies costs one call and
not the rest of the suite. It has no test files of its own. It does not hold state between lines:
the library is stateless.
