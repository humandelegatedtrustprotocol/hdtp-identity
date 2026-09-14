package pactidentity

// The address guard of §3 and §14.2: no loopback, link-local, private or unspecified host, and never
// the receiver's own endpoint from a guest. Names are checked as written; resolution is the host's,
// which applies IPIsPrivate to what it resolves.

import (
	"net/netip"
	"strings"
)

func parseIP(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a
}

var privateRanges = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8",
	"fc00::/7", "fe80::/10",
}

// IPIsPrivate reports whether an IP literal is one the guard refuses: loopback, link-local, private
// (RFC 1918), carrier-grade NAT, unspecified, unique-local, or an IPv4-mapped form of any of them.
func IPIsPrivate(ip string) bool {
	a := parseIP(strings.TrimSuffix(strings.TrimPrefix(ip, "["), "]"))
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsPrivate() || a.IsUnspecified() || a.IsMulticast() {
		return true
	}
	for _, r := range privateRanges {
		p, err := netip.ParsePrefix(r)
		if err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

// AddressGuard vets an endpoint before intake or a dial. selfEndpoint is the receiver's own; guest says
// the caller is not a pinned contact, for whom the receiver's own address is never a valid claim.
func AddressGuard(endpoint, selfEndpoint string, guest bool) (bool, string) {
	if !IsNormalHTTPS(endpoint) {
		return false, "endpoint is not an https URL in normal form"
	}
	host := hostOf(endpoint)
	bare := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false, "host is loopback"
	}
	if a := parseIP(bare); a.IsValid() && IPIsPrivate(bare) {
		return false, "host is a loopback, link-local or private address"
	}
	if guest && selfEndpoint != "" && endpoint == selfEndpoint {
		return false, "a guest's endpoint is the receiver's own"
	}
	return true, ""
}
