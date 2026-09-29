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
// (RFC 1918), carrier-grade NAT, unspecified, unique-local, an IPv4-mapped form of any of them, or an
// IPv6 literal with a zone id. One leading `[` and one trailing `]` are dropped, as a URL writes an
// IPv6 host; text that is no address — a zone on an IPv4 address or an empty one included, as netip
// reads them — is not private.
func IPIsPrivate(ip string) bool {
	a := parseIP(strings.TrimSuffix(strings.TrimPrefix(ip, "["), "]"))
	if !a.IsValid() {
		return false
	}
	// A zone is an interface scope (RFC 4007 §6), which no global address carries: a literal with one
	// is never a public address, whatever the address is. netip judged `fe80::1%eth0` by its address
	// and `2001:db8::1%eth0` as public, and the core could not read either and answered false, so a
	// resolver's zoned link-local answer was public to the Wasm.
	if a.Zone() != "" {
		return true
	}
	a = a.Unmap()
	// An IPv6 literal that EMBEDS an IPv4 address is judged by it, because a translator will dial it:
	// the NAT64 well-known prefix 64:ff9b::/96 (`[64:ff9b::7f00:1]` is 127.0.0.1 on any NAT64 network),
	// 6to4 2002::/16, and the deprecated IPv4-compatible ::/96. NAT64's LOCAL-use prefix 64:ff9b:1::/48
	// and deprecated site-local fec0::/10 are never public whatever they hold. As `address.rs`.
	if a.Is6() {
		b := a.As16()
		inside := func(i int) bool { return IPIsPrivate(netip.AddrFrom4([4]byte{b[i], b[i+1], b[i+2], b[i+3]}).String()) }
		zero := func(from, to int) bool {
			for _, x := range b[from:to] {
				if x != 0 {
					return false
				}
			}
			return true
		}
		switch {
		case a.IsLoopback() || a.IsUnspecified():
			return true
		case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b:
			return !zero(4, 12) || inside(12)
		case b[0] == 0x20 && b[1] == 0x02:
			return inside(2)
		case zero(0, 12):
			return inside(12)
		case b[0] == 0xfe && b[1]&0xc0 == 0xc0:
			return true
		}
	}
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
