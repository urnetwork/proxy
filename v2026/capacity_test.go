package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Capacity: how many concurrent clients actually fit in a memory budget?
//
// The proxy runs in a CHILD process and we measure its RSS. That isolation is the
// whole point: hosting the client and the backend in the same process as the
// proxy would fold their memory into the measurement and roughly triple it.
//
// We ramp concurrency and fit the MARGINAL cost — (RSS(n2) - RSS(n1)) / (n2 - n1)
// — rather than dividing a single RSS by n. The marginal cost excludes the Go
// runtime's fixed baseline, which is what makes it safe to extrapolate.
//
// Run it explicitly (it is slow and opens tens of thousands of sockets):
//
//	PROXY_CAPACITY=1 go test -run TestCapacity -timeout 30m -v ./
//
// Do NOT run it under -race: the detector multiplies memory per goroutine and the
// numbers become meaningless.

const memoryBudget = 8 << 30 // the 8GiB per-process cap we are sizing against

func TestMain(m *testing.M) {
	if role := os.Getenv("PROXY_CAPACITY_ROLE"); role != "" {
		runCapacityChild(role)
		return
	}
	os.Exit(m.Run())
}

// --- child process: hosts one proxy, answers control commands on stdin -------

func runCapacityChild(role string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Both legs run over unix sockets, not loopback TCP. Ephemeral ports are a
	// HOST-wide resource — only 16,384 of them — and each client needs two (the
	// client->proxy dial and the proxy->backend dial), so TCP caps this ramp at
	// ~8k clients, far too few to extrapolate an 8GiB budget from. Unix sockets
	// use no ports at all, and a client costs the same on the Go side either way:
	// the same net.Conn, bufio.Reader, relay buffers and goroutines. (Kernel
	// socket memory differs, but that lives outside RSS for both.)
	backends := strings.Split(os.Getenv("PROXY_CAPACITY_BACKEND"), ",")
	var backendNext atomic.Int64
	nextBackend := func() string {
		return backends[int(backendNext.Add(1))%len(backends)]
	}

	servedAddrs := []string{}
	if role == "socksudp" {
		// ASSOCIATE derives its BND.ADDR from the control conn's *net.TCPAddr, and
		// its egress is real udp, so this role cannot run over unix sockets.
		for i := 0; i < capacityPorts; i += 1 {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				fmt.Println("ERR", err)
				return
			}
			servedAddrs = append(servedAddrs, ln.Addr().String())
			ln.Close()
		}
	} else if role != "wg" {
		for i := 0; i < capacityPorts; i += 1 {
			servedAddrs = append(servedAddrs, capacitySocketPath("proxy", os.Getpid(), i))
		}
	}
	served := strings.Join(servedAddrs, ",")
	if served == "" {
		served = "-" // wg has no listeners: clients are peers, not connections
	}

	var wgProxy *WgProxy

	switch role {
	case "socks":
		proxy := NewSocksProxy(testSocksSettings())
		proxy.ValidUser = func(user, password, userAddr string) bool { return true }
		// no idle timeout: the whole point is to hold idle tunnels open and weigh
		// them. A read timeout would tear them down mid-ramp.
		proxy.Settings().ProxyReadTimeout = 0
		proxy.Settings().ProxyWriteTimeout = 0
		proxy.ConnectDialWithRequest = func(ctx context.Context, r SocksRequest, network string, a string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", nextBackend())
		}
		for _, addr := range servedAddrs {
			os.Remove(addr)
			go proxy.ListenAndServe(ctx, "unix", addr)
		}
	case "socksudp":
		proxy := NewSocksProxy(testSocksSettings())
		proxy.ValidUser = func(user, password, userAddr string) bool { return true }
		// no idle timeout: the whole point is to hold idle tunnels open and weigh
		// them. A read timeout would tear them down mid-ramp.
		proxy.Settings().ProxyReadTimeout = 0
		proxy.Settings().ProxyWriteTimeout = 0
		proxy.Settings().AssociateIdleTimeout = 10 * time.Minute // hold flows open for the ramp
		proxy.ConnectDialWithRequest = func(ctx context.Context, r SocksRequest, network string, a string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", nextBackend())
		}
		for _, addr := range servedAddrs {
			go proxy.ListenAndServe(ctx, "tcp", addr)
		}
	case "http":
		proxy := NewHttpProxy(testHttpSettings())
		// no idle timeout: the whole point is to hold idle tunnels open and weigh
		// them. A read timeout would tear them down mid-ramp.
		proxy.Settings().ProxyReadTimeout = 0
		proxy.Settings().ProxyWriteTimeout = 0
		proxy.ConnectDialWithRequest = func(r *http.Request, network string, a string) (net.Conn, error) {
			return (&net.Dialer{}).Dial("unix", nextBackend())
		}
		for _, addr := range servedAddrs {
			os.Remove(addr)
			go proxy.ListenAndServe(ctx, "unix", addr)
		}
	case "wg":
		settings := DefaultWgProxySettings()
		privateKey, _, err := WgGenKeyPairStrings()
		if err != nil {
			fmt.Println("ERR", err)
			return
		}
		settings.PrivateKey = privateKey
		wgProxy = NewWgProxy(ctx, settings)
		defer wgProxy.Close()
	default:
		fmt.Println("ERR unknown role", role)
		return
	}

	fmt.Println("READY", served)

	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "GC":
			// settle the heap so RSS reflects live memory rather than garbage the
			// runtime has not handed back yet
			runtime.GC()
			debug.FreeOSMemory()
			fmt.Println("OK")
		case "STATS":
			var stats runtime.MemStats
			runtime.ReadMemStats(&stats)
			fmt.Printf("OK %d %d %d %d\n",
				stats.HeapInuse, stats.StackInuse, stats.Sys, runtime.NumGoroutine())
		case "PEERS":
			// wg only: register n peers
			n, _ := strconv.Atoi(fields[1])
			addWgCapacityClients(wgProxy, n)
			fmt.Println("OK")
		case "QUIT":
			return
		default:
			fmt.Println("OK")
		}
	}
}

var wgCapacityNext int

func addWgCapacityClients(wgProxy *WgProxy, n int) {
	tun := func() (WgTun, error) { return nil, fmt.Errorf("not activated") }
	clients := map[netip.Addr]*WgClient{}
	for i := 0; i < n; i += 1 {
		wgCapacityNext += 1
		id := wgCapacityNext
		_, publicKey, err := WgGenKeyPairStrings()
		if err != nil {
			continue
		}
		addr := netip.AddrFrom4([4]byte{10, byte(id >> 16), byte(id >> 8), byte(id)})
		clients[addr] = &WgClient{
			PublicKey:  publicKey,
			ClientIpv4: addr,
			Tun:        tun,
		}
	}
	wgProxy.AddClients(clients)
}

// --- parent process: drives the child and measures it ------------------------

const capacityPorts = 8

type capacityChild struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	addrs  []string
}

func startCapacityChild(t *testing.T, role string, backend string) *capacityChild {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestCapacityNoop")
	cmd.Env = append(os.Environ(),
		"PROXY_CAPACITY_ROLE="+role,
		"PROXY_CAPACITY_BACKEND="+backend,
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}

	child := &capacityChild{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout)}
	t.Cleanup(func() {
		io.WriteString(stdin, "QUIT\n")
		cmd.Process.Kill()
		cmd.Wait()
	})

	line, err := child.stdout.ReadString('\n')
	if err != nil {
		t.Fatalf("child did not report ready: %v", err)
	}
	fields := strings.Fields(line)
	if len(fields) != 2 || fields[0] != "READY" {
		t.Fatalf("child said %q, want READY <addr>", strings.TrimSpace(line))
	}
	child.addrs = strings.Split(fields[1], ",")
	if fields[1] == "-" {
		child.addrs = nil
		return child
	}
	for _, addr := range child.addrs {
		deadline := time.Now().Add(10 * time.Second)
		for {
			conn, err := net.DialTimeout(capacityNetwork(addr), addr, time.Second)
			if err == nil {
				conn.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("child listener %s never came up: %v", addr, err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return child
}

// capacityNetwork picks the network from the address shape: the socksudp role
// serves over tcp (ASSOCIATE needs a *net.TCPAddr for its BND.ADDR), everything
// else over unix sockets to dodge ephemeral port limits.
func capacityNetwork(addr string) string {
	if strings.HasPrefix(addr, "/") {
		return "unix"
	}
	return "tcp"
}

// capacitySocketPath keeps unix socket paths short: the sun_path limit is ~104
// bytes on darwin, which a temp dir can easily blow past.
func capacitySocketPath(role string, pid int, i int) string {
	return fmt.Sprintf("/tmp/urcap-%s-%d-%d.sock", role, pid, i)
}

func (self *capacityChild) command(t *testing.T, cmd string) []string {
	t.Helper()
	if _, err := io.WriteString(self.stdin, cmd+"\n"); err != nil {
		t.Fatalf("write %q: %v", cmd, err)
	}
	line, err := self.stdout.ReadString('\n')
	if err != nil {
		t.Fatalf("read reply to %q: %v", cmd, err)
	}
	return strings.Fields(line)
}

// rss reads the child's resident set size in bytes. This is what a cgroup memory
// cap actually accounts against the process.
func (self *capacityChild) rss(t *testing.T) int64 {
	t.Helper()
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(self.cmd.Process.Pid)).Output()
	if err != nil {
		t.Skipf("cannot read child rss: %v", err)
	}
	kb, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		t.Skipf("cannot parse rss %q: %v", out, err)
	}
	return kb * 1024
}

// sample settles the child's heap, then reports its RSS and Go-side breakdown.
func (self *capacityChild) sample(t *testing.T) (rss int64, heap int64, stack int64, goroutines int64) {
	t.Helper()
	self.command(t, "GC")
	time.Sleep(200 * time.Millisecond)
	stats := self.command(t, "STATS")
	if len(stats) == 5 {
		heap, _ = strconv.ParseInt(stats[1], 10, 64)
		stack, _ = strconv.ParseInt(stats[2], 10, 64)
		goroutines, _ = strconv.ParseInt(stats[4], 10, 64)
	}
	return self.rss(t), heap, stack, goroutines
}

// TestCapacityNoop is the child's -test.run target: it must match nothing that
// does work, since the child is hijacked by TestMain before tests ever run.
func TestCapacityNoop(t *testing.T) {}

// idleBackend accepts connections and holds them open without reading or writing.
// It models the steady state we are sizing for: a large number of established
// tunnels that are mostly idle at any instant.
func idleBackend(t *testing.T) string {
	t.Helper()
	var mu sync.Mutex
	held := []net.Conn{}
	addrs := []string{}
	for i := 0; i < capacityPorts; i += 1 {
		path := capacitySocketPath("backend", os.Getpid(), i)
		os.Remove(path)
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { os.Remove(path) })
		addrs = append(addrs, path)
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				held = append(held, conn)
				mu.Unlock()
			}
		}()
	}
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			conn.Close()
		}
	})
	return strings.Join(addrs, ",")
}

type capacityStep struct {
	clients    int
	rss        int64
	heap       int64
	stack      int64
	goroutines int64
}

// report fits the marginal per-client cost across the ramp and extrapolates it to
// the memory budget.
func report(t *testing.T, name string, steps []capacityStep) {
	t.Helper()
	if len(steps) < 2 {
		t.Fatalf("%s: need at least two ramp steps", name)
	}
	base := steps[0]
	top := steps[len(steps)-1]

	t.Logf("=== %s ===", name)
	t.Logf("%10s %12s %12s %12s %12s %14s", "clients", "rss", "heap", "stack", "goroutines", "rss/client")
	for _, step := range steps {
		perClient := "-"
		if step.clients > base.clients {
			perClient = fmt.Sprintf("%.1f KiB",
				float64(step.rss-base.rss)/float64(step.clients-base.clients)/1024)
		}
		t.Logf("%10d %12s %12s %12s %12d %14s",
			step.clients, mib(step.rss), mib(step.heap), mib(step.stack), step.goroutines, perClient)
	}

	marginal := float64(top.rss-base.rss) / float64(top.clients-base.clients)
	if marginal <= 0 {
		t.Logf("%s: marginal cost is not measurable (rss did not grow)", name)
		return
	}
	// the fixed cost is whatever RSS remains once the per-client share is removed
	fixed := float64(base.rss) - marginal*float64(base.clients)
	capacity := (float64(memoryBudget) - fixed) / marginal

	t.Logf("%s: marginal %.1f KiB/client, fixed %s baseline", name, marginal/1024, mib(int64(fixed)))
	t.Logf("%s: ~%s concurrent clients fit in an 8GiB cap", name, thousands(int64(capacity)))
}

func mib(b int64) string {
	return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
}

func thousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	out := ""
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out += ","
		}
		out += string(c)
	}
	return out
}

func skipUnlessCapacity(t *testing.T) {
	t.Helper()
	if os.Getenv("PROXY_CAPACITY") == "" {
		t.Skip("set PROXY_CAPACITY=1 to run the capacity ramp (slow; opens tens of thousands of sockets)")
	}
}

var capacityRamp = []int{2000, 5000, 10000, 20000, 30000}

// --- SOCKS CONNECT -----------------------------------------------------------

func TestCapacitySocksConnect(t *testing.T) {
	skipUnlessCapacity(t)
	backend := idleBackend(t)
	child := startCapacityChild(t, "socks", backend)

	conns := []net.Conn{}
	t.Cleanup(func() {
		for _, conn := range conns {
			conn.Close()
		}
	})

	steps := []capacityStep{}
	for _, target := range capacityRamp {
		conns = append(conns, openTunnels(t, child.addrs, target-len(conns), socksTunnel)...)
		rss, heap, stack, goroutines := child.sample(t)
		steps = append(steps, capacityStep{len(conns), rss, heap, stack, goroutines})
	}
	report(t, "socks CONNECT (idle tunnels)", steps)
}

// --- HTTP CONNECT ------------------------------------------------------------

func TestCapacityHttpConnect(t *testing.T) {
	skipUnlessCapacity(t)
	backend := idleBackend(t)
	child := startCapacityChild(t, "http", backend)

	conns := []net.Conn{}
	t.Cleanup(func() {
		for _, conn := range conns {
			conn.Close()
		}
	})

	steps := []capacityStep{}
	for _, target := range capacityRamp {
		conns = append(conns, openTunnels(t, child.addrs, target-len(conns), httpTunnel)...)
		rss, heap, stack, goroutines := child.sample(t)
		steps = append(steps, capacityStep{len(conns), rss, heap, stack, goroutines})
	}
	report(t, "http CONNECT (idle tunnels)", steps)
}

// --- WireGuard peers ---------------------------------------------------------

// TestCapacityWgPeers measures REGISTERED peers: the device peer plus the proxy's
// bookkeeping. It deliberately does not activate a tun, because an active client's
// tun is a gVisor netstack owned by `connect`, not by this package — that cost is
// per-ACTIVE-client and has to be sized separately.
func TestCapacityWgPeers(t *testing.T) {
	skipUnlessCapacity(t)
	child := startCapacityChild(t, "wg", "")

	steps := []capacityStep{}
	registered := 0
	for _, target := range []int{2000, 5000, 10000, 20000} {
		child.command(t, fmt.Sprintf("PEERS %d", target-registered))
		registered = target
		rss, heap, stack, goroutines := child.sample(t)
		steps = append(steps, capacityStep{registered, rss, heap, stack, goroutines})
	}
	report(t, "wireguard (registered peers, no active tun)", steps)
}

// --- tunnel openers ----------------------------------------------------------

type tunnelFunc func(t *testing.T, proxyAddr string) (net.Conn, error)

// openTunnels establishes n tunnels concurrently and returns them, held open.
func openTunnels(t *testing.T, proxyAddrs []string, n int, open tunnelFunc) []net.Conn {
	t.Helper()
	if n <= 0 {
		return nil
	}
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, n)
	sem := make(chan struct{}, 128)
	var wg sync.WaitGroup
	for i := 0; i < n; i += 1 {
		proxyAddr := proxyAddrs[i%len(proxyAddrs)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			// a listener backlog can transiently refuse a dial at this concurrency;
			// that is a property of the harness, not the proxy, so retry briefly
			var conn net.Conn
			var err error
			for attempt := 0; attempt < 5; attempt += 1 {
				conn, err = open(t, proxyAddr)
				if err == nil {
					break
				}
				time.Sleep(time.Duration(20*(attempt+1)) * time.Millisecond)
			}
			results <- result{conn, err}
		}()
	}
	wg.Wait()
	close(results)

	conns := []net.Conn{}
	failures := 0
	var lastErr error
	for r := range results {
		if r.err != nil {
			failures += 1
			lastErr = r.err
			continue
		}
		conns = append(conns, r.conn)
	}
	if failures > 0 {
		t.Fatalf("%d of %d tunnels failed to open (last: %v)", failures, n, lastErr)
	}
	return conns
}

func socksTunnel(t *testing.T, proxyAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout(capacityNetwork(proxyAddr), proxyAddr, 20*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		conn.Close()
		return nil, err
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		conn.Close()
		return nil, err
	}
	auth := []byte{0x01, 0x01, 'u', 0x01, 'p'}
	if _, err := conn.Write(auth); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		conn.Close()
		return nil, err
	}

	host := "capacity.test"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], 443)
	req = append(req, port[:]...)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, err
	}
	if head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks reply %#x", head[1])
	}
	// consume the bind address
	switch head[3] {
	case 0x01:
		_, err = io.ReadFull(conn, make([]byte, 4+2))
	case 0x04:
		_, err = io.ReadFull(conn, make([]byte, 16+2))
	case 0x03:
		l := make([]byte, 1)
		if _, err = io.ReadFull(conn, l); err == nil {
			_, err = io.ReadFull(conn, make([]byte, int(l[0])+2))
		}
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func httpTunnel(t *testing.T, proxyAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout(capacityNetwork(proxyAddr), proxyAddr, 20*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	fmt.Fprintf(conn, "CONNECT capacity.test:443 HTTP/1.1\r\nHost: capacity.test:443\r\n\r\n")
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.Contains(status, "200") {
		conn.Close()
		return nil, fmt.Errorf("connect status %q", strings.TrimSpace(status))
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		if line == "\r\n" {
			break
		}
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// --- SOCKS UDP ASSOCIATE ------------------------------------------------------

// udpEchoBackend answers every datagram, so each flow the proxy opens is a live,
// established udp conn.
func udpEchoBackend(t *testing.T) string {
	t.Helper()
	addrs := []string{}
	for i := 0; i < capacityPorts; i += 1 {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		t.Cleanup(func() { conn.Close() })
		addrs = append(addrs, conn.LocalAddr().String())
		go func(conn *net.UDPConn) {
			buf := make([]byte, 2048)
			for {
				n, peer, err := conn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				conn.WriteToUDP(buf[:n], peer)
			}
		}(conn)
	}
	return strings.Join(addrs, ",")
}

// capacityAssociation is one client's UDP ASSOCIATE: a tcp control conn that holds the
// capacityAssociation open, a udp socket, and the relay address to send datagrams to.
type capacityAssociation struct {
	control net.Conn
	udp     *net.UDPConn
	relay   *net.UDPAddr
}

// TestCapacitySocksAssociate measures UDP ASSOCIATE, which is the memory-heaviest
// path by a wide margin: every flow parks a full-size datagram buffer
// (maxDatagramHeaderLen + 65535 bytes) for the flow's entire lifetime.
//
// The capacityAssociation count is held FIXED and the flows per capacityAssociation are ramped,
// so the slope is the per-flow cost directly — that is the number that decides
// capacity, because AssociateMaxFlows lets a single client hold hundreds of them.
func TestCapacitySocksAssociate(t *testing.T) {
	skipUnlessCapacity(t)
	backend := udpEchoBackend(t)
	child := startCapacityChild(t, "socksudp", backend)

	const associations = 200

	// baseline BEFORE any client exists, so per-capacityAssociation cost is not polluted
	// by the runtime's fixed overhead
	baseRss, baseHeap, _, _ := child.sample(t)

	assocs := []*capacityAssociation{}
	t.Cleanup(func() {
		for _, a := range assocs {
			a.control.Close()
			a.udp.Close()
		}
	})
	for i := 0; i < associations; i += 1 {
		assocs = append(assocs, openAssociation(t, child.addrs[i%len(child.addrs)]))
	}

	type flowStep struct {
		flows      int
		rss        int64
		heap       int64
		goroutines int64
	}
	steps := []flowStep{}
	flowsEach := 0
	for _, targetFlows := range []int{0, 1, 2, 4, 8, 16} {
		for _, a := range assocs {
			for f := flowsEach; f < targetFlows; f += 1 {
				// each distinct destination is a distinct flow in the NAT table
				dst := &socksUdpAddr{ip: net.IPv4(10, 8, byte(f>>8), byte(f)).To4(), port: 5000 + f}
				sendAssociateDatagram(t, a, dst)
			}
		}
		flowsEach = targetFlows
		// let the flows establish (each is a dial plus a reader goroutine)
		time.Sleep(2 * time.Second)

		rss, heap, _, goroutines := child.sample(t)
		steps = append(steps, flowStep{associations * flowsEach, rss, heap, goroutines})
	}

	t.Logf("=== socks UDP ASSOCIATE (%d associations) ===", associations)
	t.Logf("%10s %12s %12s %12s", "flows", "rss", "heap", "goroutines")
	for _, step := range steps {
		t.Logf("%10d %12s %12s %12d", step.flows, mib(step.rss), mib(step.heap), step.goroutines)
	}

	zero := steps[0] // associations established, no flows yet
	top := steps[len(steps)-1]

	perAssociationRss := float64(zero.rss-baseRss) / float64(associations)
	perAssociationHeap := float64(zero.heap-baseHeap) / float64(associations)
	perFlowRss := float64(top.rss-zero.rss) / float64(top.flows)
	perFlowHeap := float64(top.heap-zero.heap) / float64(top.flows)

	t.Logf("per capacityAssociation: %.1f KiB rss, %.1f KiB heap", perAssociationRss/1024, perAssociationHeap/1024)
	t.Logf("per flow:        %.1f KiB rss, %.1f KiB heap", perFlowRss/1024, perFlowHeap/1024)
	t.Logf("NOTE: each flow holds a %.1f KiB datagram buffer for its life (a %d byte payload limit, plus the "+
		"largest SOCKS header and the sentinel byte that makes an oversize datagram detectable). rss counts "+
		"only pages actually touched, so a flow carrying small datagrams is cheaper resident than allocated; "+
		"a flow carrying max-size datagrams touches the whole buffer. At this size the buffer is no longer "+
		"the dominant per-flow cost — the flow's goroutine stack is.",
		float64(udpCapBufLen())/1024, DefaultSocksProxySettings().MaxDatagramSize)

	// worst case is what the cap must survive: a client that fills its NAT table,
	// with every buffer fully touched
	worstPerFlow := math.Max(perFlowRss, float64(udpCapBufLen()))
	t.Logf("at the default AssociateMaxFlows=%d, one client holds ~%s resident (typical), ~%s worst case",
		DefaultSocksProxySettings().AssociateMaxFlows,
		mib(int64(perFlowRss*512)), mib(int64(worstPerFlow*512)))
	t.Logf("=> ~%s clients per 8GiB at 4 flows each (typical)",
		thousands(int64(float64(memoryBudget)/(perAssociationRss+perFlowRss*4))))
	t.Logf("=> ~%s clients per 8GiB if every client fills its NAT table (worst case)",
		thousands(int64(float64(memoryBudget)/(perAssociationRss+worstPerFlow*512))))
}

// udpCapBufLen is socks5's actual per-flow datagram buffer, so the report cannot
// drift from the implementation.
func udpCapBufLen() int {
	return socksMaxUdpBufferSize(DefaultSocksProxySettings().MaxDatagramSize)
}

type socksUdpAddr struct {
	ip   net.IP
	port int
}

func openAssociation(t *testing.T, proxyAddr string) *capacityAssociation {
	t.Helper()
	conn, err := net.DialTimeout(capacityNetwork(proxyAddr), proxyAddr, 20*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	conn.Write([]byte{0x05, 0x01, 0x02})
	io.ReadFull(conn, make([]byte, 2))
	conn.Write([]byte{0x01, 0x01, 'u', 0x01, 'p'})
	io.ReadFull(conn, make([]byte, 2))

	// ASSOCIATE with an unspecified source
	conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("associate reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("associate reply = %#x", reply[1])
	}
	port := int(reply[8])<<8 | int(reply[9])
	conn.SetDeadline(time.Time{})

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp client: %v", err)
	}
	return &capacityAssociation{
		control: conn,
		udp:     udp,
		// the child binds its relay on the control conn's local ip (127.0.0.1)
		relay: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
	}
}

func sendAssociateDatagram(t *testing.T, a *capacityAssociation, dst *socksUdpAddr) {
	t.Helper()
	datagram := []byte{0, 0, 0, 0x01}
	datagram = append(datagram, dst.ip...)
	datagram = append(datagram, byte(dst.port>>8), byte(dst.port))
	datagram = append(datagram, []byte("x")...)
	if _, err := a.udp.WriteToUDP(datagram, a.relay); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
}
