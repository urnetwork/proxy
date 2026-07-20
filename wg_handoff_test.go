package proxy

// Endpoint-handoff recovery for the wg proxy (PROXYDRAIN1.md §3.4).
//
// Scenario: a standard wireguard client has an established session with
// server A. A exports its peer statuses (learned endpoint + last handshake).
// A is killed and B starts on the same address and key — the deploy
// replacement. B registers the peer WITH the exported endpoint and initiates
// the handshake from the SERVER side.
//
// The client never has to notice the dead session on its own: it answers the
// server's initiation immediately, so traffic must resume well inside the
// ~15s dead-session detection (KeepaliveTimeout + RekeyTimeout) that the
// client-driven path (wg_restart_test.go) waits out.

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/userwireguard/conn"
	uwgdevice "github.com/urnetwork/userwireguard/device"
	"github.com/urnetwork/userwireguard/logger"
	"github.com/urnetwork/userwireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWgProxyEndpointHandoffRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("endpoint handoff test takes ~30s")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	serverPrivate, serverPublic, err := WgGenKeyPairStrings()
	if err != nil {
		t.Fatalf("generate server keypair: %v", err)
	}
	clientPrivate, clientPublic, err := WgGenKeyPair()
	if err != nil {
		t.Fatalf("generate client keypair: %v", err)
	}

	clientIP := netip.MustParseAddr("10.0.0.2")
	serverIP := netip.MustParseAddr("10.0.0.1")

	newServer := func(ctx context.Context, port int) (*WgProxy, <-chan error) {
		settings := DefaultWgProxySettings()
		settings.PrivateKey = serverPrivate
		wg := NewWgProxy(ctx, settings)
		errCh := make(chan error, 1)
		go func() {
			errCh <- wg.ListenAndServe("127.0.0.1", "::1", port)
		}()
		return wg, errCh
	}

	addClientPeer := func(wg *WgProxy, tun *recordingWgTun, endpoint *net.UDPAddr) {
		if _, err := wg.AddClients(map[netip.Addr]*WgClient{
			clientIP: {
				PublicKey:  clientPublic.String(),
				ClientIpv4: clientIP,
				Endpoint:   endpoint,
				Tun: func() (WgTun, error) {
					return tun, nil
				},
			},
		}); err != nil {
			t.Fatalf("add clients: %v", err)
		}
	}

	// server A
	ctxA, cancelA := context.WithCancel(ctx)
	defer cancelA()
	wgA, errChA := newServer(ctxA, 0)
	serverPort := waitForWgListenPort(t, wgA, errChA)
	tunA := newRecordingWgTun()
	addClientPeer(wgA, tunA, nil)

	// standard wireguard client
	clientTun := tuntest.NewChannelTUN()
	clientDevice := uwgdevice.NewDevice(
		clientTun.TUN(),
		conn.NewDefaultBind(),
		logger.NewLogger(logger.LogLevelError, "client: "),
	)
	t.Cleanup(clientDevice.Close)

	serverPublicKey, err := wgtypes.ParseKey(serverPublic)
	if err != nil {
		t.Fatalf("parse server public key: %v", err)
	}
	zeroPort := 0
	clientConfig := wgtypes.Config{
		PrivateKey:   &clientPrivate,
		ListenPort:   &zeroPort,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: serverPublicKey,
				Endpoint: &net.UDPAddr{
					IP:   net.IPv4(127, 0, 0, 1),
					Port: serverPort,
				},
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{
					{
						IP:   net.IP(serverIP.AsSlice()),
						Mask: net.CIDRMask(32, 32),
					},
				},
			},
		},
	}
	if err := clientDevice.IpcSet(&clientConfig); err != nil {
		t.Fatalf("configure client device: %v", err)
	}
	if err := clientDevice.Up(); err != nil {
		t.Fatalf("bring client device up: %v", err)
	}

	// the client sends a data packet every 500ms for the duration of the test
	go func() {
		packet := udpIPv4Packet(clientIP, serverIP, []byte("client-data"))
		for {
			select {
			case <-ctx.Done():
				return
			case clientTun.Outbound <- packet:
			case <-time.After(time.Second):
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	}()

	// session established with A
	tunA.waitSent(t)
	t.Logf("session established with server A")

	// ---- export: the drained instance's half of the handoff ----
	peerStatuses, err := wgA.PeerStatuses()
	if err != nil {
		t.Fatalf("peer statuses: %v", err)
	}
	peerStatus, ok := peerStatuses[clientIP]
	if !ok {
		t.Fatalf("no peer status for %s", clientIP)
	}
	if peerStatus.Endpoint == nil {
		t.Fatalf("peer status has no learned endpoint")
	}
	if peerStatus.LastHandshake.IsZero() {
		t.Fatalf("peer status has no last handshake")
	}
	t.Logf("exported endpoint %s (last handshake %v ago)", peerStatus.Endpoint, time.Since(peerStatus.LastHandshake).Round(time.Millisecond))

	// restart: kill A, bring up B on the same port + key
	cancelA()
	_ = wgA.Close()
	select {
	case <-errChA:
	case <-time.After(5 * time.Second):
		t.Fatal("server A did not stop")
	}
	restartTime := time.Now()

	ctxB, cancelB := context.WithCancel(ctx)
	defer cancelB()
	wgB, errChB := newServer(ctxB, serverPort)
	waitForWgListenPort(t, wgB, errChB)
	tunB := newRecordingWgTun()

	// ---- apply: the replacement instance's half of the handoff ----
	// register the peer WITH the exported endpoint, then initiate from the
	// server side. There is no conntrack in this loopback setup, so the
	// initiation reaches the client immediately — in production the device's
	// own retries (RekeyTimeout pace) cover the window until warpctl's
	// conntrack flush lets one through.
	addClientPeer(wgB, tunB, peerStatus.Endpoint)
	if err := wgB.InitiateHandshake(clientIP); err != nil {
		t.Fatalf("initiate handshake: %v", err)
	}

	// traffic must resume well inside the client's ~15s dead-session
	// detection: the client answers the server initiation immediately and its
	// next 500ms data tick rides the new session.
	handoffDeadline := 10 * time.Second
	select {
	case <-tunB.sent:
		elapsed := time.Since(restartTime)
		t.Logf("handoff ok: traffic resumed %v after restart", elapsed.Round(100*time.Millisecond))
		if handoffDeadline <= elapsed {
			t.Fatalf("handoff took %v, want well under the client's dead-session detection", elapsed)
		}
	case <-time.After(handoffDeadline):
		t.Fatalf("tunnel did not recover within %v after the endpoint handoff", handoffDeadline)
	}

	// reverse path: server B -> client over the server-initiated session
	proxyToClientPacket := udpIPv4Packet(serverIP, clientIP, []byte("proxy-to-client"))
	receive := tunB.waitReceive(t)
	select {
	case receive <- proxyToClientPacket:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out queueing packet to wg device")
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-clientTun.Inbound:
			if string(got[len(got)-len("proxy-to-client"):]) == "proxy-to-client" {
				t.Logf("reverse path ok: client received server packet on handed-off session")
				return
			}
		case <-deadline:
			t.Fatal("client did not receive packet from the replacement server")
		}
	}
}
