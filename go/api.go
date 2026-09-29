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
	ModuleVersion = "0.4.1"
	SpecVersion   = "2.2.4"
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
	// The one grammar (parseInstantZ): time.RFC3339 took an offset `now` in every function.
	t, ok := parseInstantZ(*s)
	if !ok {
		return time.Time{}, parseError{"not an RFC 3339 instant: " + *s}
	}
	return t, nil
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
// loneSurrogateWhy is what Call answers arguments holding an unpaired UTF-16 surrogate escape.
const loneSurrogateWhy = "args: a string holds half of a UTF-16 surrogate pair"

func Call(name string, args json.RawMessage) (out json.RawMessage) {
	defer func() {
		if r := recover(); r != nil {
			out = fail("internal", fmt.Sprint(r))
		}
	}()
	// A \u escape of half a surrogate pair: encoding/json reads it as U+FFFD, and the Rust core's
	// parser refuses it, so the two ports answered it two ways. Both name it first, in these words,
	// before anything reads the arguments or the name.
	if loneSurrogate(args) {
		return fail(codeArgs, loneSurrogateWhy)
	}
	fn, found := functions[name]
	if !found {
		return fail("unsupported", "no function named "+name)
	}
	// Arguments are an object, or the member is not there at all. A list, a bare scalar or the literal
	// `null` is a caller's mistake named here, once, rather than as whatever encoding/json says about
	// the struct it failed to fill — which leaks a Go type into an answer the Rust core gives in four
	// words. `null` belongs with the rest: the Rust core's `call` matches an object or refuses, and an
	// absent `args` is a zero-length message, still distinguishable, so nothing else moves.
	// js/parity.mjs holds the Rust core to the same answers (js/cases/dispatcher.mjs).
	if t := bytes.TrimSpace(args); len(t) > 0 && t[0] != '{' {
		return fail(codeArgs, "args is a JSON object")
	}
	a, bad := readArgs(args)
	if bad != nil {
		return bad
	}
	// A member the function does not declare, before any member is read (CONTRACT §0), named as the
	// Rust core names it: the first in sorted order.
	if k := stranger(a, fn.members); k != "" {
		return fail(codeArgs, name+" takes no member \""+k+"\"")
	}
	return fn.call(a)
}

// function is one name of the dispatcher: the members contract/contract.json declares for it (its
// `params.properties`, in order; TestEveryFunctionDeclaresTheContractsMembers holds the two equal,
// as the core's `every_function_declares_the_contracts_members` holds api.rs's `declared`), and
// the body in api_<section>.go that answers it.
type function struct {
	members []string
	call    func(args) json.RawMessage
}

// viaJSON is a body that still reads its arguments from their JSON text, handed the object Call
// read. It goes as each section moves to reading `args`.
func viaJSON(body func(json.RawMessage) json.RawMessage) func(args) json.RawMessage {
	return func(a args) json.RawMessage {
		raw, err := json.Marshal(map[string]json.RawMessage(a))
		if err != nil {
			return fail("internal", err.Error())
		}
		return body(raw)
	}
}

// functions is the dispatcher: every name contract/contract.json declares, grouped by its sections,
// each naming the function in api_<section>.go that answers it.
var functions = map[string]function{
	// The build: api_build.go
	"version": {nil, viaJSON(callVersion)},

	// Keys: api_keys.go
	"generate_key":  {[]string{"alg"}, viaJSON(callGenerateKey)},
	"prf_salt":      {nil, viaJSON(callPrfSalt)},
	"derive_seed":   {[]string{"prf", "info"}, viaJSON(callDeriveSeed)},
	"key_from_seed": {[]string{"alg", "seed"}, viaJSON(callKeyFromSeed)},
	"public_key":    {[]string{"pkcs8"}, viaJSON(callPublicKey)},
	"key_info":      {[]string{"spki"}, viaJSON(callKeyInfo)},
	"sign":          {[]string{"pkcs8", "data"}, viaJSON(callSign)},
	"verify":        {[]string{"spki", "data", "sig"}, viaJSON(callVerify)},

	// Certificates: api_certificates.go
	"build_root":        {[]string{"cn", "pkcs8", "not_before", "serial"}, viaJSON(callBuildRoot)},
	"root_tbs":          {[]string{"cn", "spki", "not_before", "serial"}, viaJSON(callRootTBS)},
	"assemble_root":     {[]string{"tbs", "sig", "sig_alg"}, viaJSON(assembleFn)},
	"assemble_leaf":     {[]string{"tbs", "sig", "sig_alg"}, viaJSON(assembleFn)},
	"build_leaf":        {[]string{"cn", "root_cn", "host_spki", "endpoint", "dns_name", "not_before", "not_after", "serial", "root_pkcs8"}, viaJSON(callBuildLeaf)},
	"leaf_tbs":          {[]string{"cn", "root_cn", "host_spki", "endpoint", "dns_name", "not_before", "not_after", "serial", "root_spki"}, viaJSON(callLeafTBS)},
	"parse_certificate": {[]string{"der"}, viaJSON(callParseCertificate)},
	"profile_error":     {[]string{"der", "kind"}, viaJSON(callProfileError)},
	"validate_chain":    {[]string{"chain", "now", "expected_root", "expected_endpoint"}, viaJSON(callValidateChain)},
	"compare_leaves":    {[]string{"pinned", "presented"}, viaJSON(callCompareLeaves)},
	"is_normal_https":   {[]string{"url"}, viaJSON(callIsNormalHTTPS)},
	"address_guard":     {[]string{"endpoint", "self_endpoint", "guest"}, viaJSON(callAddressGuard)},
	"ip_is_private":     {[]string{"ip"}, viaJSON(callIPIsPrivate)},

	// Certificate signing requests: api_csr.go
	"csr_new":            {[]string{"cn", "host_pkcs8", "endpoint", "dns_name"}, viaJSON(callCSRNew)},
	"csr_check":          {[]string{"der", "root_spkis"}, viaJSON(callCSRCheck)},
	"issue_from_csr":     {[]string{"csr", "root_cn", "root_spkis", "now", "previous_not_before", "valid_days", "root_pkcs8"}, viaJSON(callIssueFromCSR)},
	"issue_tbs_from_csr": {[]string{"csr", "root_cn", "root_spkis", "now", "previous_not_before", "valid_days", "root_spki"}, viaJSON(callIssueTBSFromCSR)},

	// Signing requests: api_signing.go
	"signing_request_check": {[]string{"request", "origin", "now", "root_spkis"}, viaJSON(callSigningRequestCheck)},

	// Cards: api_cards.go
	"card_encode": {[]string{"fn", "cert", "seal", "extra"}, viaJSON(callCardEncode)},
	"card_decode": {[]string{"vcard", "now"}, viaJSON(callCardDecode)},

	// Envelopes: api_envelopes.go
	"suite_for":      {[]string{"spki"}, viaJSON(callSuiteFor)},
	"hpke_seal":      {[]string{"suite", "recipient_spki", "info", "aad", "plaintext", "ephemeral_seed"}, viaJSON(callHPKESeal)},
	"hpke_open":      {[]string{"suite", "recipient_pkcs8", "recipient_spki", "info", "aad", "enc", "ct"}, viaJSON(callHPKEOpen)},
	"seal_request":   {[]string{"recipient_leaf", "sender_pkcs8", "form", "sender_chain", "msg_id", "ts", "exp", "ephemeral_seed", "method", "params", "cty"}, viaJSON(callSealRequest)},
	"seal_result":    {[]string{"recipient_spki", "sender_pkcs8", "form", "sender_chain", "msg_id", "ts", "exp", "ephemeral_seed", "result", "error"}, viaJSON(callSealResult)},
	"open_result":    {[]string{"envelope", "my_pkcs8", "my_spki", "msg_id", "now", "pins", "expected_root", "expected_endpoint"}, viaJSON(callOpenResult)},
	"follow_renewed": {[]string{"answer", "pinned_root", "pinned_leaf", "dialed", "now"}, viaJSON(callFollowRenewed)},
	"decide":         {[]string{"now", "envelope", "node"}, viaJSON(callDecide)},

	// Vault: api_vault.go
	"vault_seal":   {[]string{"passphrase", "plaintext", "kdf", "salt", "nonce"}, viaJSON(callVaultSeal)},
	"vault_open":   {[]string{"passphrase", "vault"}, viaJSON(callVaultOpen)},
	"wallet_issue": {[]string{"vault_plaintext", "record_plaintext", "root_fingerprint", "csr", "now", "valid_days", "move"}, viaJSON(callWalletIssue)},

	// Export: api_export.go
	"export_read":           {[]string{"directory", "manifest", "contacts_csv", "threads_csv", "owner", "now"}, callExportRead},
	"export_read_messages":  {[]string{"lines", "threads", "contacts", "media", "first_line"}, callExportReadMessages},
	"export_read_end":       {[]string{"manifest", "messages_sha256", "lines", "ids", "msg_ids", "reply_tos", "media_seen", "media"}, callExportReadEnd},
	"export_write":          {[]string{"owner", "owner_name", "exported_at", "tool", "contacts", "threads", "media"}, callExportWrite},
	"export_write_messages": {[]string{"messages", "msg_ids"}, callExportWriteMessages},
	"export_manifest":       {[]string{"partial", "hashes", "messages"}, callExportManifest},
	"book_rows":             {[]string{"contacts", "exported_at"}, callBookRows},
	"export_merge":          {[]string{"held", "rows"}, callExportMerge},

	// Ledger: api_ledger.go
	"ledger_check": {[]string{"ledger", "root", "endpoint", "now", "move"}, viaJSON(callLedgerCheck)},

	// Limits: api_limits.go
	"limits_rules_check": {[]string{"rules"}, callLimitsRulesCheck},
	"limits_decide":      {[]string{"rules", "charge", "now", "state"}, callLimitsDecide},
}
