// These tests pin WireGuard's borrowed-buffer and ready-only batching
// contracts at the userwireguard/Connect ownership boundary.
package proxy

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/urnetwork/connect/v2026"
)

// Records complete borrowed calls synchronously without retaining production
// buffers beyond the call.
type recordingBatchWgTun struct {
	active              bool
	updateActivityCount int
	receiveSetCount     int
	batchOffsets        []int
	batchPackets        [][][]byte
	acceptedPacketCount int
}

func (self *recordingBatchWgTun) Active() bool {
	return self.active
}

func (self *recordingBatchWgTun) UpdateActivity() bool {
	self.updateActivityCount += 1
	return true
}

func (self *recordingBatchWgTun) Cancel() {
}

func (self *recordingBatchWgTun) Send(packet []byte) bool {
	self.batchOffsets = append(self.batchOffsets, 0)
	self.batchPackets = append(self.batchPackets, [][]byte{bytes.Clone(packet)})
	return true
}

func (self *recordingBatchWgTun) SendBorrowedBatch(packets [][]byte, offset int) int {
	packetCopies := make([][]byte, len(packets))
	for packetIndex, packet := range packets {
		packetCopies[packetIndex] = bytes.Clone(packet[offset:])
	}
	self.batchOffsets = append(self.batchOffsets, offset)
	self.batchPackets = append(self.batchPackets, packetCopies)
	if self.acceptedPacketCount < 0 {
		return len(packets)
	}
	return min(self.acceptedPacketCount, len(packets))
}

func (self *recordingBatchWgTun) SetReceive(receive chan []byte) {
	self.receiveSetCount += 1
}

// Creates the minimal live proxy state needed to exercise data dispatch.
func newBatchTestWgProxy(
	packetBatchSize int,
	activeTuns map[netip.Addr]WgTun,
) *WgProxy {
	settings := DefaultWgProxySettings()
	settings.UploadPacketBatchSize = packetBatchSize
	settings.DownloadPacketBatchSize = packetBatchSize
	return &WgProxy{
		ctx:           context.Background(),
		settings:      settings,
		receive:       make(chan []byte, 256),
		clients:       map[netip.Addr]*WgClient{},
		activeClients: activeTuns,
	}
}

// Directional defaults preserve WireGuard's larger device batch while using
// the independently measured upload and ready-download bounds.
func TestWgProxyDirectionalPacketBatchDefaults(t *testing.T) {
	settings := DefaultWgProxySettings()
	wg := &WgProxy{settings: settings}
	if got := wg.uploadPacketBatchSize(); got != 8 {
		t.Fatalf("upload packet batch size=%d, want 8", got)
	}
	if got := wg.downloadPacketBatchSize(); got != 64 {
		t.Fatalf("download packet batch size=%d, want 64", got)
	}
	if got := wg.BatchSize(); got != 64 {
		t.Fatalf("device batch size=%d, want 64", got)
	}

}

// A homogeneous source is activated once, passed with its original shared
// offset, and divided only at the configured group bound.
func TestWgProxyWritePreservesHomogeneousBorrowedBatch(t *testing.T) {
	const offset = 16
	const packetCount = 128
	clientAddr := netip.MustParseAddr("10.0.0.2")
	destinationAddr := netip.MustParseAddr("192.0.2.1")
	tun := &recordingBatchWgTun{active: true, acceptedPacketCount: -1}
	wg := newBatchTestWgProxy(64, map[netip.Addr]WgTun{clientAddr: tun})
	packets := make([][]byte, packetCount)
	wantPackets := make([][]byte, packetCount)
	for packetIndex := range packets {
		packet := udpIPv4Packet(
			clientAddr,
			destinationAddr,
			[]byte{byte(packetIndex)},
		)
		packets[packetIndex] = append(make([]byte, offset), packet...)
		wantPackets[packetIndex] = packet
	}

	sentPacketCount, err := wg.Write(packets, offset)
	if err != nil || sentPacketCount != packetCount {
		t.Fatalf("sent packets=%d/%d: %v", sentPacketCount, packetCount, err)
	}
	if tun.updateActivityCount != 1 || tun.receiveSetCount != 1 {
		t.Fatalf(
			"activation count=%d receive set count=%d, want 1/1",
			tun.updateActivityCount,
			tun.receiveSetCount,
		)
	}
	if len(tun.batchPackets) != 2 ||
		len(tun.batchPackets[0]) != 64 ||
		len(tun.batchPackets[1]) != 64 ||
		tun.batchOffsets[0] != offset ||
		tun.batchOffsets[1] != offset {
		t.Fatalf("batch sizes=%d/%d offsets=%v", len(tun.batchPackets[0]), len(tun.batchPackets[1]), tun.batchOffsets)
	}
	packetIndex := 0
	for _, batchPackets := range tun.batchPackets {
		for _, packet := range batchPackets {
			if !bytes.Equal(packet, wantPackets[packetIndex]) {
				t.Fatalf("packet %d changed across borrowed batch", packetIndex)
			}
			packetIndex += 1
		}
	}
}

// Interleaved sources form first-seen device groups while retaining packet
// order inside each device group and never sharing one activation.
func TestWgProxyWriteGroupsMixedSourcesByClient(t *testing.T) {
	clientAddrA := netip.MustParseAddr("10.0.0.2")
	clientAddrB := netip.MustParseAddr("10.0.0.3")
	destinationAddr := netip.MustParseAddr("192.0.2.1")
	tunA := &recordingBatchWgTun{active: true, acceptedPacketCount: -1}
	tunB := &recordingBatchWgTun{active: true, acceptedPacketCount: -1}
	wg := newBatchTestWgProxy(64, map[netip.Addr]WgTun{
		clientAddrA: tunA,
		clientAddrB: tunB,
	})
	packetA1 := udpIPv4Packet(clientAddrA, destinationAddr, []byte("a1"))
	packetB1 := udpIPv4Packet(clientAddrB, destinationAddr, []byte("b1"))
	packetA2 := udpIPv4Packet(clientAddrA, destinationAddr, []byte("a2"))

	sentPacketCount, err := wg.Write([][]byte{packetA1, packetB1, packetA2}, 0)
	if err != nil || sentPacketCount != 3 {
		t.Fatalf("sent packets=%d/3: %v", sentPacketCount, err)
	}
	if tunA.updateActivityCount != 1 || tunB.updateActivityCount != 1 {
		t.Fatalf("activation counts=%d/%d, want 1/1", tunA.updateActivityCount, tunB.updateActivityCount)
	}
	if len(tunA.batchPackets) != 1 || len(tunA.batchPackets[0]) != 2 ||
		!bytes.Equal(tunA.batchPackets[0][0], packetA1) ||
		!bytes.Equal(tunA.batchPackets[0][1], packetA2) {
		t.Fatalf("client a groups=%v", tunA.batchPackets)
	}
	if len(tunB.batchPackets) != 1 || len(tunB.batchPackets[0]) != 1 ||
		!bytes.Equal(tunB.batchPackets[0][0], packetB1) {
		t.Fatalf("client b groups=%v", tunB.batchPackets)
	}
}

// Partial group admission reports the exact accepted count and preserves the
// established did-not-send signal for userwireguard.
func TestWgProxyWriteReportsPartialBorrowedBatch(t *testing.T) {
	clientAddr := netip.MustParseAddr("10.0.0.2")
	destinationAddr := netip.MustParseAddr("192.0.2.1")
	tun := &recordingBatchWgTun{active: true, acceptedPacketCount: 1}
	wg := newBatchTestWgProxy(64, map[netip.Addr]WgTun{clientAddr: tun})
	packets := [][]byte{
		udpIPv4Packet(clientAddr, destinationAddr, []byte("first")),
		udpIPv4Packet(clientAddr, destinationAddr, []byte("second")),
	}

	sentPacketCount, err := wg.Write(packets, 0)
	if sentPacketCount != 1 || !errors.Is(err, DidNotSendError) {
		t.Fatalf("sent packets=%d error=%v, want 1/did-not-send", sentPacketCount, err)
	}
}

// One blocking read takes the first packet and then drains exactly the ready
// bound in FIFO order, returning every channel owner to the message pool.
func TestWgProxyReadReadyDrainsConfiguredBound(t *testing.T) {
	const packetCount = 10
	wg := newBatchTestWgProxy(8, map[netip.Addr]WgTun{})
	witnesses := make([][]byte, packetCount)
	for packetIndex := range packetCount {
		packet := connect.MessagePoolGet(128)
		for byteIndex := range packet {
			packet[byteIndex] = byte(packetIndex)
		}
		witnesses[packetIndex] = connect.MessagePoolShareReadOnly(packet)
		wg.receive <- packet
	}
	buffers := make([][]byte, 8)
	for packetIndex := range buffers {
		buffers[packetIndex] = make([]byte, 128)
	}
	sizes := make([]int, len(buffers))

	count, err := wg.Read(buffers, sizes, 0)
	if err != nil || count != 8 || len(wg.receive) != 2 {
		t.Fatalf("first read count=%d queued=%d: %v", count, len(wg.receive), err)
	}
	for packetIndex := range count {
		if sizes[packetIndex] != 128 || buffers[packetIndex][0] != byte(packetIndex) {
			t.Fatalf("packet %d size=%d first byte=%d", packetIndex, sizes[packetIndex], buffers[packetIndex][0])
		}
	}
	secondBuffers := [][]byte{make([]byte, 128), make([]byte, 128)}
	secondSizes := make([]int, len(secondBuffers))
	count, err = wg.Read(secondBuffers, secondSizes, 0)
	if err != nil || count != 2 || len(wg.receive) != 0 {
		t.Fatalf("second read count=%d queued=%d: %v", count, len(wg.receive), err)
	}
	if secondBuffers[0][0] != 8 || secondBuffers[1][0] != 9 {
		t.Fatalf("second read order=%d/%d, want 8/9", secondBuffers[0][0], secondBuffers[1][0])
	}
	for packetIndex, witness := range witnesses {
		if !connect.MessagePoolReturn(witness) {
			t.Errorf("packet %d retained its receive-channel owner", packetIndex)
		}
	}
}
