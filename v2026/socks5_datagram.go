package proxy

import (
	"encoding/binary"
	"net"
)

// The SOCKS5 UDP request/response header (RFC 1928 §7):
//
//	+-----+------+------+----------+----------+----------+
//	| RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+-----+------+------+----------+----------+----------+
//	|  2  |  1   |  1   | Variable |     2    | Variable |
//	+-----+------+------+----------+----------+----------+
//
// datagramFixedLen is RSV(2)+FRAG(1)+ATYP(1)+PORT(2); the variable address adds
// addrWireLen-1 more (addrWireLen includes the ATYP byte).
const datagramFixedLen = 2 + 1 + 2

// maxDatagramHeaderLen bounds the header for any address type (domain: 1 length
// byte + 255). Reply buffers reserve this many bytes of prefix so the header
// and payload end up contiguous without a copy.
const maxDatagramHeaderLen = 2 + 1 + 1 + 1 + 255 + 2

// datagramHeaderLen is the exact encoded header length for destination a.
func datagramHeaderLen(a *AddrSpec) int {
	return datagramFixedLen + addrWireLen(a)
}

// parseDatagram decodes a client UDP datagram. The returned dst is a fresh copy
// (safe to retain); payload aliases b and is only valid until b is reused.
func parseDatagram(b []byte) (frag byte, dst *AddrSpec, payload []byte, err error) {
	if len(b) < 4 {
		return 0, nil, nil, errShortDatagram
	}
	frag = b[2]
	atyp := b[3]
	pos := 4
	a := &AddrSpec{}
	switch atyp {
	case atypIPv4:
		if len(b) < pos+net.IPv4len+2 {
			return 0, nil, nil, errShortDatagram
		}
		ip := make([]byte, net.IPv4len)
		copy(ip, b[pos:pos+net.IPv4len])
		a.IP = net.IP(ip)
		pos += net.IPv4len
	case atypIPv6:
		if len(b) < pos+net.IPv6len+2 {
			return 0, nil, nil, errShortDatagram
		}
		ip := make([]byte, net.IPv6len)
		copy(ip, b[pos:pos+net.IPv6len])
		a.IP = net.IP(ip)
		pos += net.IPv6len
	case atypDomain:
		if len(b) < pos+1 {
			return 0, nil, nil, errShortDatagram
		}
		dl := int(b[pos])
		pos++
		if dl == 0 {
			return 0, nil, nil, errUnrecognizedAddrType
		}
		if len(b) < pos+dl+2 {
			return 0, nil, nil, errShortDatagram
		}
		a.FQDN = string(b[pos : pos+dl])
		pos += dl
	default:
		return 0, nil, nil, errUnrecognizedAddrType
	}
	a.Port = int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	return frag, a, b[pos:], nil
}

// appendDatagramHeader appends RSV(0) + FRAG(0) + ATYP + ADDR + PORT for dst.
func appendDatagramHeader(b []byte, dst *AddrSpec) []byte {
	b = append(b, 0, 0, 0) // RSV, RSV, FRAG
	return appendAddrSpec(b, dst)
}
