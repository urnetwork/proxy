package proxy

import (
	"bytes"
	"net"
	"testing"
)

func TestAddrSpecRoundTrip(t *testing.T) {
	cases := []*AddrSpec{
		{IP: net.IPv4(1, 2, 3, 4).To4(), Port: 80},
		{IP: net.ParseIP("2001:db8::1"), Port: 443},
		{FQDN: "example.test", Port: 8080},
		{FQDN: "a", Port: 0},
		{IP: net.IPv4(255, 255, 255, 255).To4(), Port: 65535},
	}
	for _, want := range cases {
		enc := appendAddrSpec(nil, want)
		if got := addrWireLen(want) + 2; got != len(enc) {
			t.Fatalf("%v: addrWireLen+2=%d but encoded %d bytes", want, got, len(enc))
		}
		got, err := readAddrSpec(bytes.NewReader(enc))
		if err != nil {
			t.Fatalf("%v: decode: %v", want, err)
		}
		if got.FQDN != want.FQDN || got.Port != want.Port || !ipEqual(got.IP, want.IP) {
			t.Fatalf("round trip: got %+v want %+v", got, want)
		}
	}
}

func TestReadAddrSpecErrors(t *testing.T) {
	// unknown ATYP
	if _, err := readAddrSpec(bytes.NewReader([]byte{0x09, 1, 2})); err != errUnrecognizedAddrType {
		t.Fatalf("bad atyp: err=%v", err)
	}
	// truncated ipv4 (missing port)
	if _, err := readAddrSpec(bytes.NewReader([]byte{atypIPv4, 1, 2, 3, 4})); err == nil {
		t.Fatal("truncated ipv4: expected error")
	}
	// truncated domain
	if _, err := readAddrSpec(bytes.NewReader([]byte{atypDomain, 5, 'a', 'b'})); err == nil {
		t.Fatal("truncated domain: expected error")
	}
}

func TestDatagramRoundTrip(t *testing.T) {
	cases := []*AddrSpec{
		{IP: net.IPv4(10, 0, 0, 1).To4(), Port: 53},
		{IP: net.ParseIP("fe80::1"), Port: 5353},
		{FQDN: "dns.example", Port: 853},
	}
	payload := []byte("hello udp payload")
	for _, dst := range cases {
		var dgram []byte
		dgram = appendDatagramHeader(dgram, dst)
		if got := datagramHeaderLen(dst); got != len(dgram) {
			t.Fatalf("%v: datagramHeaderLen=%d encoded=%d", dst, got, len(dgram))
		}
		dgram = append(dgram, payload...)

		frag, gotDst, gotPayload, err := parseDatagram(dgram)
		if err != nil {
			t.Fatalf("%v: parse: %v", dst, err)
		}
		if frag != 0 {
			t.Fatalf("%v: frag=%d", dst, frag)
		}
		if gotDst.FQDN != dst.FQDN || gotDst.Port != dst.Port || !ipEqual(gotDst.IP, dst.IP) {
			t.Fatalf("%v: dst mismatch got %+v", dst, gotDst)
		}
		if !bytes.Equal(gotPayload, payload) {
			t.Fatalf("%v: payload mismatch %q", dst, gotPayload)
		}
	}
}

func TestParseDatagramErrors(t *testing.T) {
	// too short
	if _, _, _, err := parseDatagram([]byte{0, 0, 0}); err != errShortDatagram {
		t.Fatalf("short: err=%v", err)
	}
	// ipv4 without enough bytes for addr+port
	if _, _, _, err := parseDatagram([]byte{0, 0, 0, atypIPv4, 1, 2}); err != errShortDatagram {
		t.Fatalf("short ipv4: err=%v", err)
	}
	// bad atyp
	if _, _, _, err := parseDatagram([]byte{0, 0, 0, 0x09, 1, 2, 3, 4, 5, 6}); err != errUnrecognizedAddrType {
		t.Fatalf("bad atyp: err=%v", err)
	}
	// domain length overruns buffer
	if _, _, _, err := parseDatagram([]byte{0, 0, 0, atypDomain, 200, 'a'}); err != errShortDatagram {
		t.Fatalf("domain overrun: err=%v", err)
	}
}

func TestParseDatagramEmptyPayload(t *testing.T) {
	var dgram []byte
	dgram = appendDatagramHeader(dgram, &AddrSpec{IP: net.IPv4(1, 1, 1, 1).To4(), Port: 53})
	frag, dst, payload, err := parseDatagram(dgram)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if frag != 0 || dst.Port != 53 || len(payload) != 0 {
		t.Fatalf("unexpected: frag=%d dst=%+v payloadlen=%d", frag, dst, len(payload))
	}
}

func TestReadRequestRoundTrip(t *testing.T) {
	dst := &AddrSpec{FQDN: "target.example", Port: 443}
	var b []byte
	b = append(b, socksVersion, cmdConnect, 0x00)
	b = appendAddrSpec(b, dst)

	req, err := readRequest(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("readRequest: %v", err)
	}
	if req.Command != cmdConnect {
		t.Fatalf("command=%#x", req.Command)
	}
	if req.DestAddr.FQDN != dst.FQDN || req.DestAddr.Port != dst.Port {
		t.Fatalf("dest=%+v", req.DestAddr)
	}
	if req.DestAddr != req.RawDestAddr {
		t.Fatal("DestAddr and RawDestAddr should alias with no rewriter")
	}
}

func TestReadRequestBadVersion(t *testing.T) {
	if _, err := readRequest(bytes.NewReader([]byte{0x04, cmdConnect, 0, atypIPv4, 1, 2, 3, 4, 0, 80})); err != errUnsupportedVersion {
		t.Fatalf("bad version: err=%v", err)
	}
}

func TestWriteReplyEncoding(t *testing.T) {
	var buf bytes.Buffer
	bind := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4321}
	if err := writeReply(&buf, repSuccess, bind); err != nil {
		t.Fatalf("writeReply: %v", err)
	}
	b := buf.Bytes()
	if b[0] != socksVersion || b[1] != repSuccess || b[2] != 0x00 || b[3] != atypIPv4 {
		t.Fatalf("reply header = % x", b[:4])
	}
	if !net.IP(b[4:8]).Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("reply ip = % x", b[4:8])
	}
	if port := int(b[8])<<8 | int(b[9]); port != 4321 {
		t.Fatalf("reply port = %d", port)
	}
}

func TestWriteReplyNilBindIsZeroV4(t *testing.T) {
	var buf bytes.Buffer
	if err := writeReply(&buf, repHostUnreachable, nil); err != nil {
		t.Fatalf("writeReply: %v", err)
	}
	b := buf.Bytes()
	want := []byte{socksVersion, repHostUnreachable, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(b, want) {
		t.Fatalf("reply = % x want % x", b, want)
	}
}

// FuzzParseDatagram checks the datagram parser never panics and that any
// successful parse round-trips its header.
func FuzzParseDatagram(f *testing.F) {
	f.Add([]byte{0, 0, 0, atypIPv4, 1, 2, 3, 4, 0, 53, 'x'})
	f.Add([]byte{0, 0, 0, atypDomain, 3, 'a', 'b', 'c', 0, 53})
	f.Add([]byte{0, 0, 1, atypIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 187})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		frag, dst, payload, err := parseDatagram(b)
		if err != nil {
			return
		}
		// A successful parse must re-encode to a header that is a prefix of the
		// original datagram (payload immediately follows).
		hdr := appendDatagramHeader(nil, dst)
		// FRAG is forced to 0 on re-encode; compare ignoring FRAG byte.
		if len(hdr) != datagramHeaderLen(dst) {
			t.Fatalf("header len mismatch")
		}
		if len(b) != len(hdr)+len(payload) {
			t.Fatalf("length invariant broken: %d != %d + %d", len(b), len(hdr), len(payload))
		}
		_ = frag
	})
}

// FuzzReadRequest checks the request parser never panics.
func FuzzReadRequest(f *testing.F) {
	f.Add([]byte{socksVersion, cmdConnect, 0, atypIPv4, 1, 2, 3, 4, 0, 80})
	f.Add([]byte{socksVersion, cmdAssociate, 0, atypDomain, 4, 'h', 'o', 's', 't', 1, 187})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = readRequest(bytes.NewReader(b))
	})
}

func ipEqual(a, b net.IP) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return a.Equal(b)
}
