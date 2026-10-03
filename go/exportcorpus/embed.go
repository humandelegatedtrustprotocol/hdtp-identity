// Package exportcorpus is the fixture corpus of the export (SPEC §9.2; CONTRACT §6.2): a valid
// export, a valid book, and one hostile file per check of §9.2's validation, each naming the refusal
// it must produce (cases.json). Both ports' tests, js/parity.mjs and the hosts that import
// hdtp-identity read all of it; build.go makes it, and gen/ writes it here.
package exportcorpus

import "embed"

// FS holds cases.json and every file it names.
//
//go:embed cases.json *.zip
var FS embed.FS
