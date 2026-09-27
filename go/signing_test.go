package pactidentity

import (
	"bytes"
	"testing"
	"time"
)

var signingNow = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

func signingRequest(t *testing.T) (map[string]any, []byte, *PrivateKey) {
	t.Helper()
	root, _ := KeyFromSeed(AlgEd25519, Seed("signing/root"))
	cert, err := BuildRoot(RootOpts{CN: "Alina Rao", Key: root, NotBefore: signingNow})
	if err != nil {
		t.Fatal(err)
	}
	host, _ := KeyFromSeed(AlgP256, Seed("signing/host"))
	csr, err := CSRNew("Alina Rao", host, "https://agent.alina.example/mcp", "")
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"csr": B64url(csr), "purpose": "move", "expect_root": Fingerprint(root.Public.SPKI), "root_cert": B64url(cert),
		"redirect": "http://localhost:8080/wallet/return", "state": B64url(bytes.Repeat([]byte{7}, 32)), "recipient": "a node",
		"valid_days": "90", "expires": timeOut(signingNow.Add(5 * time.Minute)),
	}, root.Public.SPKI, root
}

func TestSigningRequestCheckPassesOneRequestAndRefusesOnePerRule(t *testing.T) {
	r, spki, root := signingRequest(t)
	got, err := SigningRequestCheck(r, "http://localhost:8080", signingNow, nil)
	if err != nil || got.Purpose != "move" || got.ValidDays != 90 {
		t.Fatalf("the control: %v %+v", err, got)
	}
	with := func(k string, v any) map[string]any {
		c := map[string]any{}
		for kk, vv := range r {
			c[kk] = vv
		}
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	for _, tc := range []struct {
		req    map[string]any
		origin string
		want   string
	}{
		{with("extra", "x"), "http://localhost:8080", "a signing request does not carry extra"},
		{with("valid_days", 90), "http://localhost:8080", "valid_days is a string, as a form carries it"},
		{with("state", nil), "http://localhost:8080", "state is required"},
		{r, "null", "the request has no origin: a wallet answers only the origin that asked"},
		{r, "http://localhost:8081", "the redirect's origin is not the origin that asked"},
		{with("redirect", "http://node.example/r"), "http://node.example", "the redirect is not https, or http to a loopback host"},
		{with("expires", timeOut(signingNow)), "http://localhost:8080", "the request has expired"},
		{with("expires", timeOut(signingNow.Add(601*time.Second))), "http://localhost:8080", "the request expires more than ten minutes ahead"},
		{with("purpose", "signup"), "http://localhost:8080", "purpose is renew or move"},
		{with("valid_days", "399"), "http://localhost:8080", "valid_days is a whole number of days from 1 to 398"},
	} {
		if _, err := SigningRequestCheck(tc.req, tc.origin, signingNow, nil); err == nil || err.Error() != tc.want {
			t.Errorf("want %q, got %v", tc.want, err)
		}
	}
	own, _ := CSRNew("Alina Rao", root, "https://agent.alina.example/mcp", "")
	if _, err := SigningRequestCheck(with("csr", B64url(own)), "http://localhost:8080", signingNow, [][]byte{spki}); err == nil || err.Error() != "the request's key is a root" {
		t.Errorf("the root's own key: %v", err)
	}
}

func TestRedirectAllowedIsHTTPSOrHTTPToLoopbackOnly(t *testing.T) {
	for redirect, origin := range map[string]string{
		"https://node.alina.example/r":      "https://node.alina.example",
		"https://node.alina.example:443/r":  "https://node.alina.example",
		"https://node.alina.example:8443/r": "https://node.alina.example:8443",
		"http://localhost:8080/r":           "http://localhost:8080",
		"http://127.0.0.1/r":                "http://127.0.0.1",
		"http://127.255.0.9:9/r":            "http://127.255.0.9:9",
		"http://[::1]:8080/r":               "http://[::1]:8080",
	} {
		if got, err := redirectAllowed(redirect); err != nil || got != origin {
			t.Errorf("%s: %q %v", redirect, got, err)
		}
	}
	for _, redirect := range []string{
		"http://node.alina.example/r", "http://10.0.0.1/r", "http://127.1/r", "http://0127.0.0.1/r", "http://127.0.0.256/r",
		"http://[::2]/r", "http://sub.localhost/r", "ftp://localhost/r", "//localhost/r", "http://user@localhost/r",
		"http://localhost/r#f", "http://LOCALHOST/r", "http://localhost:0/r", "http://localhost:99999/r", "http://localhost:80a/r",
		"http://localhost\\@evil.example/", "http://localhost/ r", "http://localhost/é",
		"https://[2001:DB8::1]/r", "https://node..alina.example/r", "https://.alina.example/r", "https://alina.example./r",
	} {
		if _, err := redirectAllowed(redirect); err == nil {
			t.Errorf("%s was allowed", redirect)
		}
	}
}
