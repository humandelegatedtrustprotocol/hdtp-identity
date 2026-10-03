package hdtpidentity

// Two strictness rules the Rust core applies and this port mirrors, so a chain reads the same in
// both: an envelope's lifetime is bounded (§13.1), and an Ed25519 point of small order — a public
// key or a signature's R that the cofactor sends to the identity — is not a key at all.

import "filippo.io/edwards25519"

// MaxLifetimeSeconds is §13.1's `exp − ts ≤ 30 days`: no receiver is asked to keep a msg_id for ever.
const MaxLifetimeSeconds = 30 * 86400

// ed25519PointOK reports whether 32 bytes are a canonical encoding of a point that is not of small
// order — what ed25519-dalek's verify_strict requires of A and R, and crypto/ed25519 does not.
func ed25519PointOK(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	var p edwards25519.Point
	if _, err := p.SetBytes(b); err != nil {
		return false
	}
	if p.Bytes()[0] != b[0] || string(p.Bytes()) != string(b) {
		return false // a non-canonical encoding of a point
	}
	var q edwards25519.Point
	return q.MultByCofactor(&p).Equal(edwards25519.NewIdentityPoint()) == 0
}
