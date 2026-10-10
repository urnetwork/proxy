package proxy

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
)

// AddrSpec is a SOCKS5 address: either an IP or a domain name, plus a port.
//
// The field layout mirrors what external callers of the proxy already depend
// on (they read AuthContext.Payload and DestAddr.FQDN), so it is preserved
// deliberately.
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

// String returns a host:port suitable for dialing, preferring the IP and
// falling back to the FQDN.
func (a *AddrSpec) String() string {
	if a == nil {
		return ""
	}
	if len(a.IP) != 0 {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// clone returns a deep copy so the address can safely outlive any buffer it was
// decoded from (the reply path retains the destination for the flow's lifetime).
func (a *AddrSpec) clone() *AddrSpec {
	if a == nil {
		return nil
	}
	c := &AddrSpec{FQDN: a.FQDN, Port: a.Port}
	if a.IP != nil {
		c.IP = append(net.IP(nil), a.IP...)
	}
	return c
}

// readAddrSpec decodes ATYP + ADDR + PORT from a stream. Retained bytes
// (domain, IP) are always copied out of the reader's buffers.
func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return nil, err
	}
	a := &AddrSpec{}
	switch atyp[0] {
	case atypIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		a.IP = net.IP(buf)
	case atypIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		a.IP = net.IP(buf)
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return nil, err
		}
		if l[0] == 0 {
			return nil, errUnrecognizedAddrType
		}
		dom := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, dom); err != nil {
			return nil, err
		}
		a.FQDN = string(dom)
	default:
		return nil, errUnrecognizedAddrType
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return nil, err
	}
	a.Port = int(binary.BigEndian.Uint16(port[:]))
	return a, nil
}

// addrWireLen is the encoded length of the ATYP+ADDR bytes for a, excluding the
// 2-byte port. It classifies by the stored IP length (not To4) so encoding
// preserves the address type the peer used — this must stay exactly consistent
// with appendAddrSpec, since the reply path sizes buffers from it.
func addrWireLen(a *AddrSpec) int {
	switch {
	case a != nil && a.FQDN != "":
		return 1 + 1 + len(a.FQDN)
	case a != nil && len(a.IP) == net.IPv6len:
		return 1 + net.IPv6len
	case a != nil && len(a.IP) == net.IPv4len:
		return 1 + net.IPv4len
	default:
		return 1 + net.IPv4len
	}
}

// appendAddrSpec appends ATYP + ADDR + PORT for a, classifying by stored IP
// length so a peer's address type round-trips exactly. A nil or unusable
// address is encoded as 0.0.0.0:port.
func appendAddrSpec(b []byte, a *AddrSpec) []byte {
	port := 0
	switch {
	case a != nil && a.FQDN != "":
		b = append(b, atypDomain, byte(len(a.FQDN)))
		b = append(b, a.FQDN...)
		port = a.Port
	case a != nil && len(a.IP) == net.IPv6len:
		b = append(b, atypIPv6)
		b = append(b, a.IP...)
		port = a.Port
	case a != nil && len(a.IP) == net.IPv4len:
		b = append(b, atypIPv4)
		b = append(b, a.IP...)
		port = a.Port
	default:
		b = append(b, atypIPv4, 0, 0, 0, 0)
	}
	return append(b, byte(port>>8), byte(port))
}

// appendReplyAddr appends a bind address (from a net.Addr) as ATYP+ADDR+PORT.
func appendReplyAddr(b []byte, addr net.Addr) []byte {
	var ip net.IP
	var port int
	switch v := addr.(type) {
	case *net.TCPAddr:
		ip, port = v.IP, v.Port
	case *net.UDPAddr:
		ip, port = v.IP, v.Port
	}
	if ip4 := ip.To4(); ip4 != nil {
		b = append(b, atypIPv4)
		b = append(b, ip4...)
	} else if len(ip) == net.IPv6len {
		b = append(b, atypIPv6)
		b = append(b, ip...)
	} else {
		b = append(b, atypIPv4, 0, 0, 0, 0)
	}
	return append(b, byte(port>>8), byte(port))
}
