package hdtpidentity

// The build section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name.

import "encoding/json"

// The build, not a rule: the one function whose answer is allowed to differ between the ports,
// because it describes the port. Every other name in the functions map must answer as the Rust core
// answers.
func callVersion(args) json.RawMessage {
	return ok(map[string]any{"module": ModuleVersion, "spec": SpecVersion})
}
