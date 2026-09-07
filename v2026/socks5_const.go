// A minimal SOCKS5 server built from RFC 1928 / RFC 1929,
// implementing exactly the subset the proxy needs: method negotiation (no-auth
// and username/password), CONNECT, and UDP ASSOCIATE. The protocol codecs are
// dependency-free so they can be fuzzed in isolation; the CONNECT data path
// shares the proxies' one relay implementation (internal/relay) so its
// cancellation semantics cannot drift from the http proxy's.
//
// The UDP ASSOCIATE relay is the reason this package exists: it maintains a
// bounded, idle-evicted NAT table with per-flow error isolation, routes all
// egress through the caller-supplied Dial (so associate traffic goes through
// the same tunnel as CONNECT), and tears everything down deterministically when
// the TCP control connection closes. See associate.go.
package proxy

import "errors"

// SOCKS protocol version.
const socksVersion = 0x05

// Request commands (RFC 1928 §4).
const (
	cmdConnect   = 0x01
	cmdBind      = 0x02
	cmdAssociate = 0x03
)

// Address types (RFC 1928 §5).
const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// Authentication methods (RFC 1928 §3).
const (
	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF
)

// Username/password auth (RFC 1929).
const (
	userPassVersion = 0x01
	authSuccess     = 0x00
	authFailure     = 0x01
)

// Reply codes (RFC 1928 §6). Exported so callers can map dial errors.
const (
	repSuccess              uint8 = 0x00
	repServerFailure        uint8 = 0x01
	repRuleFailure          uint8 = 0x02
	repNetworkUnreachable   uint8 = 0x03
	repHostUnreachable      uint8 = 0x04
	repConnectionRefused    uint8 = 0x05
	repTTLExpired           uint8 = 0x06
	repCommandNotSupported  uint8 = 0x07
	repAddrTypeNotSupported uint8 = 0x08
)

var (
	errUnsupportedVersion   = errors.New("socks5: unsupported version")
	errNoMethods            = errors.New("socks5: no authentication methods offered")
	errNoAcceptableAuth     = errors.New("socks5: no acceptable authentication method")
	errAuthFailed           = errors.New("socks5: authentication failed")
	errUnrecognizedAddrType = errors.New("socks5: unrecognized address type")
	errShortDatagram        = errors.New("socks5: short udp datagram")
)
