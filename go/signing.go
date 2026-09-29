package pactidentity

// Signing requests (SPEC §9.1 in 2.2.0; CONTRACT §3.1): a host asking a web wallet for a leaf with
// a form POSTed by top-level navigation. SigningRequestCheck is everything the wallet can decide
// about one before a person sees it, in the order the Rust core decides it: the request's members
// and their bounds, the asking origin against the redirect, the redirect's scheme and host, the
// expiry window, and the CSR through CSRCheck. What it cannot decide stays the wallet's: proving
// the root against expect_root, showing the person what they sign, and the validity they choose.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// The members of a signing request, as its form carries them: every one a string.
var (
	signingMembers  = []string{"csr", "purpose", "expect_root", "root_cert", "redirect", "state", "recipient", "valid_days", "expires"}
	signingRequired = []string{"csr", "purpose", "expect_root", "redirect", "state", "recipient", "valid_days", "expires"}
	// Bytes for the base64url and URL members, characters (Unicode scalar values) for recipient.
	signingLimits = map[string]int{"csr": 4096, "purpose": 16, "expect_root": 64, "root_cert": 4096, "redirect": 2048, "state": 43, "recipient": 200, "valid_days": 3, "expires": 40}
)

// SigningMaxAhead is how far ahead a request may expire.
const SigningMaxAhead = 10 * time.Minute

// SigningChecked is what a request that passed says.
type SigningChecked struct {
	CSR       string
	Redirect  string
	Purpose   string
	ValidDays int
}

type signingRefusal struct{ why string }

func (e signingRefusal) Error() string { return e.why }

func refuseSigning(why string) error { return signingRefusal{why} }

func isB64url(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// loopbackHost is a host a redirect may name over http: localhost, a dotted quad in 127.0.0.0/8 in
// the normal form (four decimal octets, no leading zero), or [::1].
func loopbackHost(host string) bool {
	if host == "localhost" || host == "[::1]" {
		return true
	}
	octets := strings.Split(host, ".")
	if len(octets) != 4 || octets[0] != "127" {
		return false
	}
	for _, o := range octets {
		if o == "" || len(o) > 3 || !allDigits(o) || (len(o) > 1 && o[0] == '0') {
			return false
		}
		if n, _ := strconv.Atoi(o); n > 255 {
			return false
		}
	}
	return true
}

// redirectAllowed answers the redirect's origin (scheme://host[:port], the port left out when it
// is the scheme's default), if the redirect is one a wallet may navigate to: absolute, ASCII, no
// userinfo, no fragment, and https, or http only to a loopback host.
func redirectAllowed(redirect string) (string, error) {
	for i := 0; i < len(redirect); i++ {
		if c := redirect[i]; c < 0x21 || c > 0x7e || c == '\\' {
			return "", refuseSigning("the redirect is not an absolute URL")
		}
	}
	if strings.Contains(redirect, "#") {
		return "", refuseSigning("the redirect carries a fragment")
	}
	var scheme, rest string
	switch {
	case strings.HasPrefix(redirect, "https://"):
		scheme, rest = "https", redirect[len("https://"):]
	case strings.HasPrefix(redirect, "http://"):
		scheme, rest = "http", redirect[len("http://"):]
	default:
		return "", refuseSigning("the redirect is not https, or http to a loopback host")
	}
	end := strings.IndexAny(rest, "/?")
	if end < 0 {
		end = len(rest)
	}
	authority, path := rest[:end], rest[end:]
	if strings.Contains(authority, "@") {
		return "", refuseSigning("the redirect carries userinfo")
	}
	var host, port string
	if strings.HasPrefix(authority, "[") {
		i := strings.IndexByte(authority, ']')
		if i < 0 {
			return "", refuseSigning("the redirect is not an absolute URL")
		}
		host, port = authority[:i+1], authority[i+1:]
	} else if i := strings.IndexByte(authority, ':'); i >= 0 {
		host, port = authority[:i], authority[i:]
	} else {
		host = authority
	}
	// Lower-case normal form (CONTRACT §3.1): an IPv6 literal's hex in lower case, and a name of
	// labels none of which is empty.
	hostOK := host != ""
	if hostOK && strings.HasPrefix(host, "[") {
		inner := host[1 : len(host)-1]
		hostOK = inner != ""
		for i := 0; i < len(inner); i++ {
			c := inner[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c == ':' || c == '.') {
				hostOK = false
			}
		}
	} else if hostOK {
		for i := 0; i < len(host); i++ {
			c := host[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
				hostOK = false
			}
		}
		// A name of labels none of which is empty: no leading, trailing or doubled dot.
		for _, label := range strings.Split(host, ".") {
			if label == "" {
				hostOK = false
			}
		}
	}
	if !hostOK {
		return "", refuseSigning("the redirect's host is not in normal form")
	}
	portN := 0
	if port != "" {
		digits := port[1:]
		if port[0] != ':' || digits == "" || len(digits) > 5 || !allDigits(digits) || digits[0] == '0' {
			return "", refuseSigning("the redirect's port is not in normal form")
		}
		n, err := strconv.Atoi(digits)
		if err != nil || n < 1 || n > 65535 {
			return "", refuseSigning("the redirect's port is not in normal form")
		}
		portN = n
	}
	if !(path == "" || path[0] == '/' || path[0] == '?') {
		return "", refuseSigning("the redirect is not an absolute URL")
	}
	if scheme == "http" && !loopbackHost(host) {
		return "", refuseSigning("the redirect is not https, or http to a loopback host")
	}
	def := 443
	if scheme == "http" {
		def = 80
	}
	if portN != 0 && portN != def {
		return fmt.Sprintf("%s://%s:%d", scheme, host, portN), nil
	}
	return scheme + "://" + host, nil
}

// SigningRequestCheck applies the checks to a decoded request (a JSON object's members), in the
// order CONTRACT §3.1 writes them. A refusal names the first thing wrong. No request at all (nil) is
// `request is required`, as the core's `check` answers a request that is not an object; it was
// judged as an empty one here and named its first member, `csr is required` (T21).
func SigningRequestCheck(request map[string]any, origin string, now time.Time, rootSPKIs [][]byte) (*SigningChecked, error) {
	if request == nil {
		return nil, refuseSigning("request is required")
	}
	var strangers []string
	for k := range request {
		known := false
		for _, m := range signingMembers {
			known = known || k == m
		}
		if !known {
			strangers = append(strangers, k)
		}
	}
	sort.Strings(strangers)
	if len(strangers) > 0 {
		return nil, refuseSigning("a signing request does not carry " + strangers[0])
	}
	text := map[string]string{}
	for _, m := range signingMembers {
		v, has := request[m]
		if !has {
			continue
		}
		s, isText := v.(string)
		if !isText {
			return nil, refuseSigning(m + " is a string, as a form carries it")
		}
		size := len(s)
		if m == "recipient" {
			size = utf8.RuneCountInString(s)
		}
		if size > signingLimits[m] {
			return nil, refuseSigning(fmt.Sprintf("%s is longer than %d", m, signingLimits[m]))
		}
		text[m] = s
	}
	for _, m := range signingRequired {
		if text[m] == "" {
			return nil, refuseSigning(m + " is required")
		}
	}
	if origin == "" || origin == "null" {
		return nil, refuseSigning("the request has no origin: a wallet answers only the origin that asked")
	}
	to, err := redirectAllowed(text["redirect"])
	if err != nil {
		return nil, err
	}
	if to != origin {
		return nil, refuseSigning("the redirect's origin is not the origin that asked")
	}
	expires, ok := parseInstantZ(text["expires"])
	if !ok {
		return nil, refuseSigning("expires is not an RFC 3339 instant")
	}
	if !expires.After(now) {
		return nil, refuseSigning("the request has expired")
	}
	if expires.After(now.Add(SigningMaxAhead)) {
		return nil, refuseSigning("the request expires more than ten minutes ahead")
	}
	purpose := text["purpose"]
	if purpose != "renew" && purpose != "move" {
		return nil, refuseSigning("purpose is renew or move")
	}
	days := text["valid_days"]
	n, err := strconv.Atoi(days)
	if err != nil || !allDigits(days) || days[0] == '0' || n < 1 || n > MaxLeafDays {
		return nil, refuseSigning("valid_days is a whole number of days from 1 to 398")
	}
	state := text["state"]
	if raw, err := decodeB64url(state); len(state) != 43 || !isB64url(state) || err != nil || len(raw) != 32 {
		return nil, refuseSigning("state is 32 bytes, base64url")
	}
	expect := text["expect_root"]
	if h, found := strings.CutPrefix(expect, "sha256:"); !found || len(h) != 43 || !isB64url(h) {
		return nil, refuseSigning("expect_root is not a root fingerprint")
	}
	if cert, has := text["root_cert"]; has {
		var der []byte
		if isB64url(cert) {
			der, err = decodeB64url(cert)
		}
		if !isB64url(cert) || err != nil {
			return nil, refuseSigning("root_cert is not base64url")
		}
		parsed, err := Parse(der)
		if err != nil {
			return nil, refuseSigning("root_cert is not a certificate")
		}
		if ProfileError(parsed, "root") != "" {
			return nil, refuseSigning("root_cert is not a root certificate")
		}
		if FingerprintOf(parsed) != expect {
			return nil, refuseSigning("root_cert is not the root expect_root names")
		}
	}
	csrText := text["csr"]
	if !isB64url(csrText) {
		return nil, refuseSigning("csr is not base64url")
	}
	der, err := decodeB64url(csrText)
	if err != nil {
		return nil, refuseSigning("not base64url")
	}
	if info := CSRCheck(der, rootSPKIs); !info.OK {
		return nil, refuseSigning(info.Why)
	}
	return &SigningChecked{CSR: csrText, Redirect: text["redirect"], Purpose: purpose, ValidDays: n}, nil
}

// parseInstantZ reads an instant in the one grammar both ports read everywhere (SPEC 2.2.2; the
// Rust core's parse_rfc3339): `YYYY-MM-DDTHH:MM:SS`, an optional `.` and one or more digits (the
// fraction is dropped: the boundary is whole seconds), and `Z` — upper-case T and Z only, no offset,
// `.` alone as the fraction separator. time.Parse is not the reader: it takes an offset, and a `,`
// before the fraction.
func parseInstantZ(s string) (time.Time, bool) {
	if len(s) < 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' {
		return time.Time{}, false
	}
	num := func(from, to int) (int, bool) {
		n := 0
		for i := from; i < to; i++ {
			if s[i] < '0' || s[i] > '9' {
				return 0, false
			}
			n = n*10 + int(s[i]-'0')
		}
		return n, true
	}
	i := 19
	if s[i] == '.' {
		i++
		start := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == start {
			return time.Time{}, false
		}
	}
	if i+1 != len(s) || s[i] != 'Z' {
		return time.Time{}, false
	}
	var f [6]int
	for k, r := range [6][2]int{{0, 4}, {5, 7}, {8, 10}, {11, 13}, {14, 16}, {17, 19}} {
		n, ok := num(r[0], r[1])
		if !ok {
			return time.Time{}, false
		}
		f[k] = n
	}
	y, mo, d, h, mi, sec := f[0], f[1], f[2], f[3], f[4], f[5]
	if mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || sec > 59 {
		return time.Time{}, false
	}
	t := time.Date(y, time.Month(mo), d, h, mi, sec, 0, time.UTC)
	if t.Year() != y || int(t.Month()) != mo || t.Day() != d {
		return time.Time{}, false
	}
	return t, true
}
