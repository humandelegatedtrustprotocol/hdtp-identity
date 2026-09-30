package pactidentity

// Call is the one boundary every home of the library presents: a function name and a JSON object in,
// one JSON object out, never a panic. The names and shapes are CONTRACT.md's.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// The port's own identity, answered by `version`. The spec version is the one thing here that must
// track the Rust core. The module version is the repository's one version (scripts/version.mjs
// writes it here and holds it equal to the crates' and the Wasm package's).
const (
	ModuleVersion = "0.4.1"
	SpecVersion   = "2.2.5"
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

// failAs is an error answered with the code CONTRACT §0 names for it (codeFor), or `fallback`.
func failAs(fallback string, err error) json.RawMessage { return failErr(codeFor(err, fallback), err) }

func ok(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		// encoding/json's words are not an answer (CONTRACT §0); the core's line for the same.
		return fail("internal", "does not serialise as JSON")
	}
	return b
}

func timeOut(t time.Time) string { return t.UTC().Format(time.RFC3339) }

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

func certOut(c *Cert) map[string]any {
	kind := "other"
	if ProfileError(c, "root") == "" {
		kind = "root"
	} else if ProfileError(c, "leaf") == "" {
		kind = "leaf"
	}
	// A certificate that is neither is judged as a root when it is a CA AND self-issued, and as a leaf
	// otherwise, as the contract's `Certificate` says and the core judges it: this judged every CA as a
	// root, so a CA-flagged leaf under another name was a root's refusal here and a leaf's there (T17).
	var profileErr any
	if kind == "other" {
		if c.CA && c.Issuer == c.Subject {
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

// loneSurrogateWhy is what Call answers arguments holding an unpaired UTF-16 surrogate escape.
const loneSurrogateWhy = "args: a string holds half of a UTF-16 surrogate pair"

// Call dispatches one contract function.
func Call(name string, args json.RawMessage) (out json.RawMessage) {
	defer func() {
		if r := recover(); r != nil {
			out = fail("internal", fmt.Sprint(r))
		}
	}()
	// The name first: one the contract does not have is `unsupported`, whatever the arguments are
	// (CONTRACT §0). The core read the arguments first, so a list, null or half a surrogate pair beside
	// an unknown name was a refusal of the arguments there and `unsupported` here (R34).
	fn, found := functions[name]
	if !found {
		return fail("unsupported", "no function named "+name)
	}
	// A \u escape of half a surrogate pair: encoding/json reads it as U+FFFD, and the Rust core's
	// parser refuses it, so the two ports answered it two ways. Both name it next, in these words,
	// before anything reads the arguments.
	if loneSurrogate(args) {
		return fail(codeArgs, loneSurrogateWhy)
	}
	// What one port's JSON parser refuses and the other's reads — a number infinite as a double, or
	// containers nested past serde_json's limit — named next, in the core's words: this port read the
	// arguments and went on where the core answered serde's text (R40, S3-2).
	if why := jsonLimit(args); why != "" {
		return fail(codeArgs, "args: "+why)
	}
	// Arguments are an object. A list, a bare scalar, the literal `null` or no text at all is a
	// caller's mistake named here, once, rather than as whatever encoding/json says about the map
	// readArgs could not fill — which leaks a Go type into an answer the Rust core gives in four words.
	// No text at all was `{}` here and `args is a JSON object` to the core's `call`; a caller that
	// means no arguments passes `{}`, as the JS loader and this port's line adapter do.
	// js/boundary-text.json holds both ports to these answers, and js/parity.mjs the rest
	// (js/cases/dispatcher.mjs).
	if t := bytes.TrimSpace(args); len(t) == 0 || t[0] != '{' {
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

// functions is the dispatcher: every name contract/contract.json declares, grouped by its sections,
// each naming the function in api_<section>.go that answers it.
var functions = map[string]function{
	// The build: api_build.go
	"version": {nil, callVersion},

	// Keys: api_keys.go
	"generate_key":  {[]string{"alg"}, callGenerateKey},
	"prf_salt":      {nil, callPrfSalt},
	"derive_seed":   {[]string{"prf", "info"}, callDeriveSeed},
	"key_from_seed": {[]string{"alg", "seed"}, callKeyFromSeed},
	"public_key":    {[]string{"pkcs8"}, callPublicKey},
	"key_info":      {[]string{"spki"}, callKeyInfo},
	"sign":          {[]string{"pkcs8", "data"}, callSign},
	"verify":        {[]string{"spki", "data", "sig"}, callVerify},

	// Certificates: api_certificates.go
	"build_root":        {[]string{"cn", "pkcs8", "not_before", "serial"}, callBuildRoot},
	"root_tbs":          {[]string{"cn", "spki", "not_before", "serial"}, callRootTBS},
	"assemble_root":     {[]string{"tbs", "sig", "sig_alg"}, assembleFn},
	"assemble_leaf":     {[]string{"tbs", "sig", "sig_alg"}, assembleFn},
	"build_leaf":        {[]string{"cn", "root_cn", "host_spki", "endpoint", "dns_name", "not_before", "not_after", "serial", "root_pkcs8"}, callBuildLeaf},
	"leaf_tbs":          {[]string{"cn", "root_cn", "host_spki", "endpoint", "dns_name", "not_before", "not_after", "serial", "root_spki"}, callLeafTBS},
	"parse_certificate": {[]string{"der"}, callParseCertificate},
	"profile_error":     {[]string{"der", "kind"}, callProfileError},
	"validate_chain":    {[]string{"chain", "now", "expected_root", "expected_endpoint"}, callValidateChain},
	"compare_leaves":    {[]string{"pinned", "presented"}, callCompareLeaves},
	"is_normal_https":   {[]string{"url"}, callIsNormalHTTPS},
	"address_guard":     {[]string{"endpoint", "self_endpoint", "guest"}, callAddressGuard},
	"ip_is_private":     {[]string{"ip"}, callIPIsPrivate},

	// Certificate signing requests: api_csr.go
	"csr_new":            {[]string{"cn", "host_pkcs8", "endpoint", "dns_name"}, callCSRNew},
	"csr_check":          {[]string{"der", "root_spkis"}, callCSRCheck},
	"issue_from_csr":     {[]string{"csr", "root_cn", "root_spkis", "now", "previous_not_before", "valid_days", "root_pkcs8"}, callIssueFromCSR},
	"issue_tbs_from_csr": {[]string{"csr", "root_cn", "root_spkis", "now", "previous_not_before", "valid_days", "root_spki"}, callIssueTBSFromCSR},

	// Signing requests: api_signing.go
	"signing_request_check": {[]string{"request", "origin", "now", "root_spkis"}, callSigningRequestCheck},

	// Cards: api_cards.go
	"card_encode":   {[]string{"fn", "cert", "seal", "extra"}, callCardEncode},
	"card_decode":   {[]string{"vcard", "now"}, callCardDecode},
	"refresh_check": {[]string{"pin", "answer", "now"}, callRefreshCheck},

	// Envelopes: api_envelopes.go
	"suite_for":      {[]string{"spki"}, callSuiteFor},
	"hpke_seal":      {[]string{"suite", "recipient_spki", "info", "aad", "plaintext", "ephemeral_seed"}, callHPKESeal},
	"hpke_open":      {[]string{"suite", "recipient_pkcs8", "recipient_spki", "info", "aad", "enc", "ct"}, callHPKEOpen},
	"seal_request":   {[]string{"recipient_leaf", "sender_pkcs8", "form", "sender_chain", "msg_id", "ts", "exp", "ephemeral_seed", "method", "params", "cty"}, callSealRequest},
	"seal_result":    {[]string{"recipient_spki", "sender_pkcs8", "form", "sender_chain", "msg_id", "ts", "exp", "ephemeral_seed", "result", "error"}, callSealResult},
	"open_result":    {[]string{"envelope", "my_pkcs8", "my_spki", "msg_id", "now", "pins", "expected_root", "expected_endpoint"}, callOpenResult},
	"follow_renewed": {[]string{"answer", "pinned_root", "pinned_leaf", "dialed", "now"}, callFollowRenewed},
	"decide":         {[]string{"now", "envelope", "node"}, callDecide},
	"decide_chain":   {[]string{"node", "chain", "now"}, callDecideChain},

	// Vault: api_vault.go
	"vault_seal":   {[]string{"passphrase", "plaintext", "kdf", "salt", "nonce"}, callVaultSeal},
	"vault_open":   {[]string{"passphrase", "vault"}, callVaultOpen},
	"wallet_issue": {[]string{"vault_plaintext", "record_plaintext", "root_fingerprint", "csr", "now", "valid_days", "move"}, callWalletIssue},

	// Export: api_export.go
	"export_read":             {[]string{"directory", "manifest", "contacts_csv", "threads_csv", "owner", "now"}, callExportRead},
	"export_read_messages":    {[]string{"lines", "threads", "contacts", "media", "first_line"}, callExportReadMessages},
	"export_read_end":         {[]string{"manifest", "messages_sha256", "lines", "ids", "msg_ids", "reply_tos", "media_seen", "media"}, callExportReadEnd},
	"export_write":            {[]string{"owner", "owner_name", "exported_at", "tool", "contacts", "threads", "media"}, callExportWrite},
	"export_write_messages":   {[]string{"messages", "msg_ids"}, callExportWriteMessages},
	"export_manifest":         {[]string{"partial", "hashes", "messages"}, callExportManifest},
	"book_rows":               {[]string{"contacts", "exported_at"}, callBookRows},
	"export_merge":            {[]string{"held", "rows"}, callExportMerge},
	"media_holds_private_key": {[]string{"bytes"}, callMediaHoldsPrivateKey},

	// Ledger: api_ledger.go
	"ledger_check": {[]string{"ledger", "root", "endpoint", "now", "move"}, callLedgerCheck},

	// Limits: api_limits.go
	"limits_rules_check": {[]string{"rules"}, callLimitsRulesCheck},
	"limits_decide":      {[]string{"rules", "charge", "now", "state"}, callLimitsDecide},
	"limits_buckets":     {[]string{"rules", "charge"}, callLimitsBuckets},
}
