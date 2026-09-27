package pactidentity

// Call is the one boundary every home of the library presents: a function name and a JSON object in,
// one JSON object out, never a panic. The names and shapes are CONTRACT.md's.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The port's own identity, answered by `version`. The spec version is the one thing here that must
// track the Rust core. The module version is the repository's one version (scripts/version.mjs
// writes it here and holds it equal to the crates' and the Wasm package's).
const (
	ModuleVersion = "0.2.0"
	SpecVersion   = "2.2.0"
)

type apiError struct {
	Error string `json:"error"`
	Why   string `json:"why"`
}

func fail(code, why string) json.RawMessage {
	b, _ := json.Marshal(apiError{Error: code, Why: why})
	return b
}

func failErr(code string, err error) json.RawMessage { return fail(code, err.Error()) }

func ok(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return fail("internal", err.Error())
	}
	return b
}

func timeOut(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// The default validity belongs to the boundary: an absent member means a year, and an explicit zero
// is refused, as the Rust core refuses it. (A Go caller of the library passes a real number or
// omits the field, which its struct cannot tell from zero — hence the pointer here.)
func daysOr(v *int) (int, error) {
	if v == nil {
		return 365, nil
	}
	if *v < 1 || *v > MaxLeafDays {
		return 0, errArg("validity must be between one and 398 days")
	}
	return *v, nil
}

// timeIn reads a REQUIRED instant. Absent, it is `<name> is required` and `bad_request`, as every
// other absent member is (CONTRACT §0) and as the core says it; this port said "an instant is
// required" and called it `parse`, in every function that takes one. Present and unreadable is `parse`.
func timeIn(s *string, name string) (time.Time, error) {
	if s == nil {
		return time.Time{}, errArg(name + " is required")
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return time.Time{}, parseError{"not an RFC 3339 instant: " + *s}
	}
	return t.Truncate(time.Second), nil
}

// A caller's arguments that will not read are a caller mistake, so they answer `bad_request` here
// and in the Rust core alike (CONTRACT §0: the same names, the same shapes, the same codes).
const codeArgs = "bad_request"

// An argument that is missing or of the wrong shape is a caller mistake; bytes that will not decode
// are a parse failure. Both ports answer the same way, so a caller reads one contract (CONTRACT §0).
type argError struct{ why string }

func (e argError) Error() string { return e.why }

func errArg(why string) error { return argError{why} }

// codeFor names an error as CONTRACT §0 names it, wherever it was raised.
func codeFor(err error, fallback string) string {
	var a argError
	if errors.As(err, &a) {
		return codeArgs
	}
	var p parseError
	if errors.As(err, &p) {
		return "parse"
	}
	var u unsupportedError
	if errors.As(err, &u) {
		return "unsupported"
	}
	var v vaultError
	if errors.As(err, &v) {
		return "vault"
	}
	return fallback
}

func decodeArgs(args json.RawMessage, into any) error {
	if len(args) == 0 {
		args = []byte("{}")
	}
	err := json.Unmarshal(args, into)
	// A member of the wrong JSON type. encoding/json says so in its own words — "json: cannot unmarshal
	// string into Go struct field sealArgs.sender_chain of type []pactidentity.B64" — which the other
	// port cannot reproduce and CONTRACT §0 says it will not have to. The core reads a member with an
	// accessor that finds nothing of the type it wants and answers `<name> is required`; so does this.
	var mismatch *json.UnmarshalTypeError
	if errors.As(err, &mismatch) {
		if mismatch.Field != "" && !strings.Contains(mismatch.Field, ".") {
			return errArg(mismatch.Field + " is required")
		}
		return errArg("arguments do not read")
	}
	return err
}

// privIn and pubIn take the member's own name so an absent key is reported the way the caller wrote
// it — `host_pkcs8 is required`, not `pkcs8 is required`, when that is the member that is missing.
// Absent is `== nil` (see b64.go): a member present as "" is not missing, it is bytes that will not
// parse, and the parser says so, as the Rust core does.
func privIn(der B64, name string) (*PrivateKey, error) {
	if der == nil {
		return nil, errArg(name + " is required")
	}
	return ParsePKCS8(der)
}

func pubIn(spki B64, name string) (*PublicKey, error) {
	if spki == nil {
		return nil, errArg(name + " is required")
	}
	pub, err := ParseSPKI(spki)
	if err != nil {
		return nil, err
	}
	if _, err := AlgorithmOf(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// need is the same rule for a member the function reads directly rather than through a key parser.
func need(b B64, name string) error {
	if b == nil {
		return errArg(name + " is required")
	}
	return nil
}

// needStr is the same rule for a string member: absent (nil) is a caller's mistake that names it.
func needStr(s *string, name string) (string, error) {
	if s == nil {
		return "", errArg(name + " is required")
	}
	return *s, nil
}

func certOut(c *Cert) map[string]any {
	kind := "other"
	if ProfileError(c, "root") == "" {
		kind = "root"
	} else if ProfileError(c, "leaf") == "" {
		kind = "leaf"
	}
	var profileErr any
	if kind == "other" {
		if c.CA {
			profileErr = ProfileError(c, "root")
		} else {
			profileErr = ProfileError(c, "leaf")
		}
	}
	var pathLen any
	if c.PathLen != nil {
		pathLen = *c.PathLen
	}
	var ski, aki any
	if c.SKI != nil {
		ski = B64url(c.SKI)
	}
	if c.AKI != nil {
		aki = B64url(c.AKI)
	}
	alg := c.PublicKey.Alg
	uris, dns, eku := c.URIs, c.DNS, c.EKU
	if uris == nil {
		uris = []string{}
	}
	if dns == nil {
		dns = []string{}
	}
	if eku == nil {
		eku = []string{}
	}
	ku := c.KeyUsage
	if ku == nil {
		ku = []int{}
	}
	exts := make([]map[string]any, 0, len(c.Extensions))
	for _, e := range c.Extensions {
		exts = append(exts, map[string]any{"id": e.ID, "critical": e.Critical})
	}
	return map[string]any{
		"kind": kind, "subject": c.Subject, "issuer": c.Issuer, "serial": B64url(c.Serial),
		"not_before": timeOut(c.NotBefore), "not_after": timeOut(c.NotAfter), "alg": alg,
		"spki": B64url(c.SPKI), "fingerprint": FingerprintOf(c), "key_id": B64url(c.KeyID),
		"ski": ski, "aki": aki, "ca": c.CA, "path_len": pathLen, "key_usage": ku, "eku": eku,
		"uris": uris, "dns": dns, "sig_alg": c.SigAlg, "profile_error": profileErr, "bytes": len(c.DER),
		"extensions": exts,
	}
}

// Call dispatches one contract function.
func Call(name string, args json.RawMessage) (out json.RawMessage) {
	defer func() {
		if r := recover(); r != nil {
			out = fail("internal", fmt.Sprint(r))
		}
	}()
	fn, found := functions[name]
	if !found {
		return fail("unsupported", "no function named "+name)
	}
	// Arguments are an object, or the member is not there at all. A list, a bare scalar or the literal
	// `null` is a caller's mistake named here, once, rather than as whatever encoding/json says about
	// the struct it failed to fill — which leaks a Go type into an answer the Rust core gives in four
	// words. `null` belongs with the rest: the Rust core's `call` matches an object or refuses, and an
	// absent `args` is a zero-length message, still distinguishable, so nothing else moves.
	//
	// This one cannot be reached through `js/parity.mjs`: its port shim does `JSON.stringify(args ?? {})`,
	// so a null never survives the trip. A case the harness cannot express lives in each port's own
	// suite instead — here and in the Rust core's `api::tests`.
	if t := bytes.TrimSpace(args); len(t) > 0 && t[0] != '{' {
		return fail(codeArgs, "args is a JSON object")
	}
	return fn(args)
}

// functions is the dispatcher: every name contract/contract.json declares, grouped by its sections,
// each naming the function in api_<section>.go that answers it.
var functions = map[string]func(json.RawMessage) json.RawMessage{
	// The build: api_build.go
	"version": callVersion,

	// Keys: api_keys.go
	"generate_key":  callGenerateKey,
	"prf_salt":      callPrfSalt,
	"derive_seed":   callDeriveSeed,
	"key_from_seed": callKeyFromSeed,
	"public_key":    callPublicKey,
	"key_info":      callKeyInfo,
	"sign":          callSign,
	"verify":        callVerify,

	// Certificates: api_certificates.go
	"build_root":        callBuildRoot,
	"root_tbs":          callRootTBS,
	"assemble_root":     assembleFn,
	"assemble_leaf":     assembleFn,
	"build_leaf":        callBuildLeaf,
	"leaf_tbs":          callLeafTBS,
	"parse_certificate": callParseCertificate,
	"profile_error":     callProfileError,
	"validate_chain":    callValidateChain,
	"compare_leaves":    callCompareLeaves,
	"is_normal_https":   callIsNormalHTTPS,
	"address_guard":     callAddressGuard,
	"ip_is_private":     callIPIsPrivate,

	// Certificate signing requests: api_csr.go
	"csr_new":            callCSRNew,
	"csr_check":          callCSRCheck,
	"issue_from_csr":     callIssueFromCSR,
	"issue_tbs_from_csr": callIssueTBSFromCSR,

	// Signing requests: api_signing.go
	"signing_request_check": callSigningRequestCheck,

	// Cards: api_cards.go
	"card_encode": callCardEncode,
	"card_decode": callCardDecode,

	// Envelopes: api_envelopes.go
	"suite_for":      callSuiteFor,
	"hpke_seal":      callHPKESeal,
	"hpke_open":      callHPKEOpen,
	"seal_request":   callSealRequest,
	"seal_result":    callSealResult,
	"open_result":    callOpenResult,
	"follow_renewed": callFollowRenewed,
	"decide":         callDecide,

	// Vault: api_vault.go
	"vault_seal":   callVaultSeal,
	"vault_open":   callVaultOpen,
	"wallet_issue": callWalletIssue,

	// Export: api_export.go
	"export_read":           callExportRead,
	"export_read_messages":  callExportReadMessages,
	"export_read_end":       callExportReadEnd,
	"export_write":          callExportWrite,
	"export_write_messages": callExportWriteMessages,
	"export_manifest":       callExportManifest,
	"book_rows":             callBookRows,
	"export_merge":          callExportMerge,

	// Ledger: api_ledger.go
	"ledger_check": callLedgerCheck,
}
