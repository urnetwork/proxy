package proxy

// Restart-recovery experiment for the wg proxy.
//
// Scenario: a standard wireguard client has an established session with the
// proxy. The proxy process is restarted (all in-memory wg state lost: sessions,
// peer table, endpoints). The new process listens on the same address with the
// same server private key. The client keeps sending data the whole time.
//
// Phase 1 (peer NOT re-added): the client's transport packets and handshake
// initiations must be silently ignored — the tunnel stays dead.
// Phase 2 (peer re-added, as the proxy_client_notification full sync does):
// the client's next handshake retry must complete and traffic must resume.

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/userwireguard/v2026/conn"
	uwgdevice "github.com/urnetwork/userwireguard/v2026/device"
	"github.com/urnetwork/userwireguard/v2026/logger"
	"github.com/urnetwork/userwireguard/v2026/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWgProxyRestartRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("restart recovery test takes ~60s")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
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

	addClientPeer := func(wg *WgProxy, tun *recordingWgTun) {
		if _, err := wg.AddClients(map[netip.Addr]*WgClient{
			clientIP: {
				PublicKey:  clientPublic.String(),
				ClientIpv4: clientIP,
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
	addClientPeer(wgA, tunA)

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

	// restart: kill A, bring up B on the same port + key with NO peers
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
	t.Logf("server B listening on port %d (no peers)", serverPort)

	// phase 1: peer not registered. The client's transport packets and, from
	// ~15s, its handshake initiations arrive at B and must be silently ignored.
	noPeerWindow := 25 * time.Second
	select {
	case packet := <-tunB.sent:
		t.Fatalf("server B received decrypted traffic without the peer registered: %v", packet)
	case <-time.After(noPeerWindow):
	}
	t.Logf("phase 1 ok: %v elapsed since restart, tunnel still dead (initiations ignored)", time.Since(restartTime).Round(time.Second))

	// phase 2: peer registered (what the proxy_client_notification full sync
	// does shortly after startup). The client's next handshake retry should
	// complete and traffic should resume.
	addClientPeer(wgB, tunB)
	peerAddTime := time.Now()

	recoverDeadline := 45 * time.Second
	select {
	case <-tunB.sent:
		t.Logf("phase 2 ok: traffic resumed %v after peer re-add (%v after restart)",
			time.Since(peerAddTime).Round(100*time.Millisecond),
			time.Since(restartTime).Round(100*time.Millisecond))
	case <-time.After(recoverDeadline):
		t.Fatalf("tunnel did not recover within %v after re-adding the peer", recoverDeadline)
	}

	// reverse path: server B -> client
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
				t.Logf("reverse path ok: client received server packet on new session")
				return
			}
			// skip unrelated packets (e.g. keepalives are not delivered to tun, but be safe)
		case <-deadline:
			t.Fatal("client did not receive packet from restarted server")
		}
	}
}
