package pactidentity

// The little DER the certificate profile needs: an encoder for building, a strict walker for reading.
// Every message here is the seed library's, verbatim, because the intrusion suite reads them.

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v & 0xff)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func tlv(tag byte, content []byte) []byte {
	out := make([]byte, 0, 2+len(content)+4)
	out = append(out, tag)
	out = append(out, derLength(len(content))...)
	return append(out, content...)
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func seq(parts ...[]byte) []byte      { return tlv(0x30, concat(parts...)) }
func set(parts ...[]byte) []byte      { return tlv(0x31, concat(parts...)) }
func explicit(n int, c []byte) []byte { return tlv(0xa0|byte(n), c) }
func implicit(n int, c []byte) []byte { return tlv(0x80|byte(n), c) }
func octet(b []byte) []byte           { return tlv(0x04, b) }
func utf8s(s string) []byte           { return tlv(0x0c, []byte(s)) }
func derBool(v bool) []byte {
	if v {
		return tlv(0x01, []byte{0xff})
	}
	return tlv(0x01, []byte{0x00})
}

// derInt encodes the big-endian magnitude bytes as a positive INTEGER (a leading zero added when the
// high bit is set), exactly as the seed's int() does for a Buffer.
func derInt(v []byte) []byte {
	if len(v) == 0 || v[0]&0x80 != 0 {
		return tlv(0x02, append([]byte{0}, v...))
	}
	return tlv(0x02, v)
}

func derIntN(n int64) []byte {
	h := strconv.FormatInt(n, 16)
	if len(h)%2 == 1 {
		h = "0" + h
	}
	b, _ := new(big.Int).SetString(h, 16)
	raw := b.Bytes()
	if len(raw) == 0 {
		raw = []byte{0}
	}
	return derInt(raw)
}

func bitstr(b []byte, unused int) []byte { return tlv(0x03, append([]byte{byte(unused)}, b...)) }

func oidBytes(s string) []byte {
	parts := strings.Split(s, ".")
	nums := make([]*big.Int, len(parts))
	for i, p := range parts {
		nums[i], _ = new(big.Int).SetString(p, 10)
	}
	first := new(big.Int).Mul(nums[0], big.NewInt(40))
	first.Add(first, nums[1])
	out := []byte{byte(first.Int64())}
	for _, v := range nums[2:] {
		b := []byte{byte(v.Int64() & 0x7f)}
		for r := new(big.Int).Rsh(v, 7); r.Sign() > 0; r.Rsh(r, 7) {
			b = append([]byte{byte(r.Int64()&0x7f) | 0x80}, b...)
		}
		out = append(out, b...)
	}
	return tlv(0x06, out)
}

// derTime writes UTCTime before 2050 and GeneralizedTime from 2050, per RFC 5280.
func derTime(t time.Time) []byte {
	t = t.UTC()
	rest := t.Format("0102150405") + "Z"
	if t.Year() < 2050 {
		return tlv(0x17, []byte(t.Format("06")+rest))
	}
	return tlv(0x18, []byte(fmt.Sprintf("%04d", t.Year())+rest))
}

type derNode struct {
	tag     byte
	content []byte
	raw     []byte
	end     int
}

// derRead reads strictly: definite and minimal lengths only, nothing past the end. Indefinite forms,
// padded lengths and trailing bytes are how one parser is made to see what another does not.
func derRead(buf []byte, pos int) (derNode, error) {
	if pos+2 > len(buf) {
		return derNode{}, errors.New("DER truncated")
	}
	tag := buf[pos]
	l := int(buf[pos+1])
	at := pos + 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 {
			return derNode{}, errors.New("DER indefinite or oversized length")
		}
		if at >= len(buf) {
			return derNode{}, errors.New("DER truncated")
		}
		if buf[at] == 0 {
			return derNode{}, errors.New("DER length not minimal")
		}
		l = 0
		for i := 0; i < n; i++ {
			if at >= len(buf) {
				return derNode{}, errors.New("DER truncated")
			}
			l = l<<8 | int(buf[at])
			at++
		}
		if l < 0x80 {
			return derNode{}, errors.New("DER length not minimal")
		}
	}
	if at+l > len(buf) {
		return derNode{}, errors.New("DER length overruns the buffer")
	}
	return derNode{tag: tag, content: buf[at : at+l], raw: buf[pos : at+l], end: at + l}, nil
}

func derChildren(n derNode) ([]derNode, error) {
	var out []derNode
	pos := 0
	for pos < len(n.content) {
		c, err := derRead(n.content, pos)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		pos = c.end
	}
	return out, nil
}

func readOid(n derNode) string {
	b := n.content
	if len(b) == 0 {
		return ""
	}
	parts := []string{strconv.Itoa(int(b[0]) / 40), strconv.Itoa(int(b[0]) % 40)}
	v := new(big.Int)
	for i := 1; i < len(b); i++ {
		v.Lsh(v, 7)
		v.Or(v, big.NewInt(int64(b[i]&0x7f)))
		if b[i]&0x80 == 0 {
			parts = append(parts, v.String())
			v = new(big.Int)
		}
	}
	return strings.Join(parts, ".")
}

var derTimeForm = regexp.MustCompile(`^\d{14}Z$`)

func readTime(n derNode) (time.Time, error) {
	s := string(n.content)
	full := s
	if n.tag == 0x17 {
		if len(s) < 2 {
			return time.Time{}, errors.New("time not in the DER form")
		}
		yy, err := strconv.Atoi(s[:2])
		if err != nil || yy < 0 {
			return time.Time{}, errors.New("time not in the DER form")
		}
		if yy < 50 {
			full = "20" + s
		} else {
			full = "19" + s
		}
	}
	if !derTimeForm.MatchString(full) {
		return time.Time{}, errors.New("time not in the DER form")
	}
	t, err := time.Parse("20060102150405Z", full)
	if err != nil {
		// The seed builds a Date from the digits without validating them; an out-of-range field rolls
		// over there and refuses here. Both are refusals of a certificate no wallet writes.
		return time.Time{}, errors.New("time not in the DER form")
	}
	return t, nil
}
