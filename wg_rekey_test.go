package proxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/userwireguard/conn"
	uwgdevice "github.com/urnetwork/userwireguard/device"
	"github.com/urnetwork/userwireguard/logger"
	"github.com/urnetwork/userwireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Rekey success alone does not prove that the established peer still reaches
// its hosted TUN. Keep the same client, endpoint, and TUN across both rekey
// directions, and require a fresh bidirectional packet exchange in each phase.
// No external service, deployment, key expiration, or packet loss is involved.
func TestWgProxyRekeyPreservesBidirectionalTunAttachment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverPrivate, serverPublic, err := WgGenKeyPairStrings()
	if err != nil {
		t.Fatal(err)
	}
	clientPrivate, clientPublic, err := WgGenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	settings := DefaultWgProxySettings()
	settings.PrivateKey = serverPrivate
	settings.CheckTunIdleTimeout = time.Minute
	settings.Log = connect.NewNoopLogger()
	wg := NewWgProxy(ctx, settings)
	t.Cleanup(func() { _ = wg.Close() })
	errCh := make(chan error, 1)
	go func() { errCh <- wg.ListenAndServe("127.0.0.1", "::1", 0) }()
	port := waitForWgListenPort(t, wg, errCh)

	clientIP := netip.MustParseAddr("10.0.0.2")
	serverIP := netip.MustParseAddr("10.0.0.1")
	proxyTun := &rekeyRecordingTun{recordingWgTun: newRecordingWgTun()}
	var opens atomic.Int32
	if err := wg.SetClients(map[netip.Addr]*WgClient{
		clientIP: {
			PublicKey:  clientPublic.String(),
			ClientIpv4: clientIP,
			Tun: func() (WgTun, error) {
				opens.Add(1)
				return proxyTun, nil
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	clientTun := tuntest.NewChannelTUN()
	clientDevice := uwgdevice.NewDevice(clientTun.TUN(), conn.NewDefaultBind(), logger.NewLogger(logger.LogLevelError, "rekey-client: "))
	t.Cleanup(clientDevice.Close)
	serverPublicKey, err := wgtypes.ParseKey(serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	zeroPort := 0
	if err := clientDevice.IpcSet(&wgtypes.Config{
		PrivateKey: &clientPrivate, ListenPort: &zeroPort, ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:         serverPublicKey,
			Endpoint:          &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{{IP: net.IP(serverIP.AsSlice()), Mask: net.CIDRMask(32, 32)}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := clientDevice.Up(); err != nil {
		t.Fatal(err)
	}

	exchange := func(phase string) {
		t.Helper()
		for i := range 8 {
			payload := bytes.Repeat([]byte{byte(i)}, 1200)
			copy(payload, fmt.Sprintf("%s/%d", phase, i))
			outbound := udpIPv4Packet(clientIP, serverIP, payload)
			select {
			case clientTun.Outbound <- outbound:
			case <-ctx.Done():
				t.Fatalf("%s: client send: %v", phase, ctx.Err())
			}
			if got := proxyTun.waitSent(t); !bytes.Equal(got, outbound) {
				t.Fatalf("%s packet %d: hosted TUN got changed data", phase, i)
			}
			inbound := udpIPv4Packet(serverIP, clientIP, payload)
			owned := connect.MessagePoolCopy(inbound)
			select {
			case proxyTun.waitReceive(t) <- owned:
			case <-ctx.Done():
				connect.MessagePoolReturn(owned)
				t.Fatalf("%s: proxy send: %v", phase, ctx.Err())
			}
			select {
			case got := <-clientTun.Inbound:
				if !bytes.Equal(got, inbound) {
					t.Fatalf("%s packet %d: client TUN got changed data", phase, i)
				}
			case <-ctx.Done():
				t.Fatalf("%s packet %d: missing inner return: %v", phase, i, ctx.Err())
			}
		}
	}
	handshake := func() time.Time {
		t.Helper()
		statuses, err := wg.PeerStatuses()
		if err != nil || statuses[clientIP] == nil {
			t.Fatalf("read peer status: %v", err)
		}
		return statuses[clientIP].LastHandshake
	}
	exchange("initial")
	initialHandshake := handshake()
	if initialHandshake.IsZero() {
		t.Fatal("initial traffic did not complete a handshake")
	}
	clientPeer := clientDevice.LookupPeer(uwgdevice.NoisePublicKey(serverPublicKey))
	if clientPeer == nil {
		t.Fatal("configured client peer disappeared")
	}
	for _, direction := range []string{"client", "server"} {
		previous := handshake()
		// Handshake initiation has a five-second anti-flood floor in both
		// directions. Poll the real public API rather than mutate private timers
		// or sleep until the 120-second key-expiration window.
		pace := time.NewTicker(25 * time.Millisecond)
		for !handshake().After(previous) {
			if direction == "client" {
				err = clientPeer.SendHandshakeInitiation(false)
			} else {
				err = wg.InitiateHandshake(clientIP)
			}
			if err != nil {
				pace.Stop()
				t.Fatalf("%s rekey: %v", direction, err)
			}
			select {
			case <-pace.C:
			case <-ctx.Done():
				pace.Stop()
				t.Fatalf("%s rekey did not complete: %v", direction, ctx.Err())
			}
		}
		pace.Stop()
		exchange(direction + "-rekey")
	}
	proxyTun.mu.Lock()
	attachmentChanges, attachmentAddr := proxyTun.attachmentChanges, proxyTun.attachmentAddr
	proxyTun.mu.Unlock()
	if opens.Load() != 1 || attachmentChanges != 1 || attachmentAddr != clientIP {
		t.Fatalf("rekey replaced TUN: opens=%d attachment changes=%d address=%s", opens.Load(), attachmentChanges, attachmentAddr)
	}
	if stats := wg.RuntimeStats(); stats != (WgRuntimeStats{}) {
		t.Fatalf("unloaded loopback traffic had receiver refusals/failures: %+v", stats)
	}
	_ = wg.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("WG listener shutdown: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("WG listener did not join: %v", ctx.Err())
	}
}

type rekeyRecordingTun struct {
	*recordingWgTun
	mu                sync.Mutex
	attachmentAddr    netip.Addr
	attachmentChannel chan []byte
	attachmentChanges int
}

func (t *rekeyRecordingTun) SetReceiveForAddress(addr netip.Addr, receive chan []byte) {
	t.mu.Lock()
	if t.attachmentAddr != addr || t.attachmentChannel != receive {
		t.attachmentChanges++
		t.attachmentAddr, t.attachmentChannel = addr, receive
	}
	t.mu.Unlock()
	t.recordingWgTun.SetReceive(receive)
}
