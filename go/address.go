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
	// `netip` has no IsBroadcast, and 255.255.255.255 is none of the above (255 & 0xf0 is 0xf0, so
	// not multicast either). Rust's v4_private calls `is_broadcast`, so the node accepted a guest
	// card at the broadcast address that the wallet refused — and `manager.go` vets a stranger's
	// endpoint with this on redeem and request.
	if a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
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

// bareHost is the host of an https URL's authority with no brackets, no userinfo and NO PORT — what
// every check below compares against a name or parses as an address.
//
// `hostOf` is the authority, port and all, which is what the dNSName rule (§14.1) and the wallet's
// same-host test want. The guard wants the other thing, and using the authority here was a hole: a
// normal-form endpoint may carry a non-default port (§14.1 omits only the default), so
// `https://127.0.0.1:8443/mcp` compared "127.0.0.1:8443" against "127.0.0.1", matched nothing,
// parsed as no address at all, and passed — while the Rust core, whose `host_of` strips the port,
// refused it. Two ports disagreeing about what is local is exactly what CONTRACT §0 forbids.
func bareHost(endpoint string) string {
	host := hostOf(endpoint)
	if i := strings.LastIndexByte(host, '@'); i >= 0 {
		host = host[i+1:]
	}
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end >= 0 {
			return host[1:end]
		}
		return strings.TrimPrefix(host, "[")
	}
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}

// AddressGuard vets an endpoint before intake or a dial. selfEndpoint is the receiver's own; guest says
// the caller is not a pinned contact, for whom the receiver's own address is never a valid claim.
func AddressGuard(endpoint, selfEndpoint string, guest bool) (bool, string) {
	// The normal form first (§14.1): every other spelling of an address — an IPv4 in decimal, hex or
	// octal, a host with an odd case — is refused here, never resolved.
	if !IsNormalHTTPS(endpoint) {
		return false, "endpoint is not an https URL in normal form"
	}
	host := strings.ToLower(strings.TrimSuffix(bareHost(endpoint), ".")) // a trailing dot names the same host
	if host == "" {
		return false, "endpoint is not an https URL"
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false, "endpoint host is local"
	}
	if a := parseIP(host); a.IsValid() && IPIsPrivate(host) {
		return false, "endpoint host is a loopback, link-local or private address"
	}
	if guest && selfEndpoint != "" && endpoint == selfEndpoint {
		return false, "a guest's endpoint names this node's own address"
	}
	return true, ""
}
