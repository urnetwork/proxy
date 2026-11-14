package proxy

import (
	"io"
	"net"
)

// AuthContext carries the authentication result into the dial callback.
// For username/password auth Payload contains "username" and "password".
type AuthContext struct {
	Method  byte
	Payload map[string]string
}

// Request is a parsed SOCKS5 request. Its shape (DestAddr, RawDestAddr,
// AuthContext, LocalAddr, RemoteAddr) matches what proxy callers already
// consume so the dial callback contract is preserved.
type Request struct {
	Command     byte
	DestAddr    *AddrSpec
	RawDestAddr *AddrSpec
	AuthContext *AuthContext
	LocalAddr   net.Addr
	RemoteAddr  net.Addr
}

// readMethods reads the client's method-selection message:
//
//	+----+----------+----------+
//	|VER | NMETHODS | METHODS  |
//	+----+----------+----------+
func readMethods(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != socksVersion {
		return nil, errUnsupportedVersion
	}
	n := int(hdr[1])
	if n == 0 {
		return nil, errNoMethods
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, err
	}
	return methods, nil
}

func containsByte(bs []byte, b byte) bool {
	for _, x := range bs {
		if x == b {
			return true
		}
	}
	return false
}

// readUserPass reads an RFC 1929 username/password request:
//
//	+----+------+----------+------+----------+
//	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//	+----+------+----------+------+----------+
func readUserPass(r io.Reader) (user, pass string, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return "", "", err
	}
	if hdr[0] != userPassVersion {
		return "", "", errUnsupportedVersion
	}
	ubuf := make([]byte, int(hdr[1]))
	if _, err = io.ReadFull(r, ubuf); err != nil {
		return "", "", err
	}
	var pl [1]byte
	if _, err = io.ReadFull(r, pl[:]); err != nil {
		return "", "", err
	}
	pbuf := make([]byte, int(pl[0]))
	if _, err = io.ReadFull(r, pbuf); err != nil {
		return "", "", err
	}
	return string(ubuf), string(pbuf), nil
}

// readRequest reads a SOCKS5 request:
//
//	+----+-----+-------+------+----------+----------+
//	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//	+----+-----+-------+------+----------+----------+
func readRequest(r io.Reader) (*Request, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != socksVersion {
		return nil, errUnsupportedVersion
	}
	dst, err := readAddrSpec(r)
	if err != nil {
		return nil, err
	}
	return &Request{
		Command:     hdr[1],
		DestAddr:    dst,
		RawDestAddr: dst,
	}, nil
}

// writeReply writes a SOCKS5 reply with the given code and bind address.
func writeReply(w io.Writer, rep uint8, bind net.Addr) error {
	b := make([]byte, 0, 3+1+net.IPv6len+2)
	b = append(b, socksVersion, rep, 0x00)
	b = appendReplyAddr(b, bind)
	_, err := w.Write(b)
	return err
}
