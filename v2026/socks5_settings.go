package proxy

// socksMaxUdpBufferSize is the per-flow datagram buffer an associate flow holds
// for its lifetime: the payload limit, plus the largest SOCKS header, plus the
// sentinel byte that makes an oversize datagram detectable (see
// socks5_associate.go).
func socksMaxUdpBufferSize(maxDatagramSize int) int {
	return socksMaxUdpReadLen(maxDatagramSize)
}
