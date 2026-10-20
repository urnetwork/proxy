// These benchmarks isolate WireGuard's borrowed-packet boundary so source
// grouping, Connect ownership copies, and ready-only reads can be compared at
// equal correctness without socket or cryptographic noise.
package proxy

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/urnetwork/connect/v2026"
)

// The singular fixture performs the ownership copy required before an
// asynchronous Connect send, then immediately completes that send.
type benchmarkSingularCopyWgTun struct {
	sentPacketCount int
}

func (self *benchmarkSingularCopyWgTun) Active() bool {
	return true
}

func (self *benchmarkSingularCopyWgTun) UpdateActivity() bool {
	return true
}

func (self *benchmarkSingularCopyWgTun) Cancel() {
}

func (self *benchmarkSingularCopyWgTun) Send(packet []byte) bool {
	ownedPacket := connect.MessagePoolCopy(packet)
	connect.MessagePoolReturn(ownedPacket)
	self.sentPacketCount += 1
	return true
}

func (self *benchmarkSingularCopyWgTun) SetReceive(receive chan []byte) {
}

// The batch fixture performs exactly the same ownership copies through one
// group call, which isolates grouping from the cost of making buffers safe.
type benchmarkBatchCopyWgTun struct {
	benchmarkSingularCopyWgTun
}

func (self *benchmarkBatchCopyWgTun) SendBorrowedBatch(packets [][]byte, offset int) int {
	for _, packet := range packets {
		ownedPacket := connect.MessagePoolCopy(packet[offset:])
		connect.MessagePoolReturn(ownedPacket)
	}
	self.sentPacketCount += len(packets)
	return len(packets)
}

// Compares the pre-batch per-packet dispatch, grouped compatibility dispatch,
// and complete group dispatch while all three pay the same required copy cost.
func BenchmarkWgProxyUploadBoundary(benchmark *testing.B) {
	for _, packetCount := range []int{1, 8, 64, 128} {
		clientAddr := netip.MustParseAddr("10.0.0.2")
		destinationAddr := netip.MustParseAddr("192.0.2.1")
		packets := make([][]byte, packetCount)
		packetByteCount := 0
		for packetIndex := range packets {
			packets[packetIndex] = udpIPv4Packet(
				clientAddr,
				destinationAddr,
				make([]byte, 1200),
			)
			packetByteCount += len(packets[packetIndex])
		}

		benchmark.Run(fmt.Sprintf("correct-singular/packets-%d", packetCount), func(benchmark *testing.B) {
			tun := &benchmarkSingularCopyWgTun{}
			settings := DefaultWgProxySettings()
			wg := &WgProxy{
				ctx:           context.Background(),
				settings:      settings,
				receive:       make(chan []byte, 128),
				clients:       map[netip.Addr]*WgClient{},
				activeClients: map[netip.Addr]WgTun{clientAddr: tun},
			}
			write := func() (int, error) {
				count := 0
				for _, packet := range packets {
					ipPath, err := connect.ParseIpPath(packet)
					if err != nil {
						return count, err
					}
					sourceAddr, ok := netip.AddrFromSlice(ipPath.SourceIp)
					if !ok {
						return count, fmt.Errorf("unknown source ip")
					}
					activeTun, err := wg.activateClient(sourceAddr)
					if err != nil {
						return count, err
					}
					if activeTun.Send(packet) {
						count += 1
					} else {
						return count, DidNotSendError
					}
				}
				return count, nil
			}

			benchmark.SetBytes(int64(packetByteCount))
			benchmark.ReportAllocs()
			benchmark.ResetTimer()
			for range benchmark.N {
				sentPacketCount, err := write()
				if err != nil || sentPacketCount != packetCount {
					benchmark.Fatalf("sent packets=%d/%d: %v", sentPacketCount, packetCount, err)
				}
			}
		})

		benchmark.Run(fmt.Sprintf("grouped-singular/packets-%d", packetCount), func(benchmark *testing.B) {
			tun := &benchmarkSingularCopyWgTun{}
			settings := DefaultWgProxySettings()
			wg := &WgProxy{
				ctx:           context.Background(),
				settings:      settings,
				receive:       make(chan []byte, 128),
				clients:       map[netip.Addr]*WgClient{},
				activeClients: map[netip.Addr]WgTun{clientAddr: tun},
			}

			benchmark.SetBytes(int64(packetByteCount))
			benchmark.ReportAllocs()
			benchmark.ResetTimer()
			for range benchmark.N {
				sentPacketCount, err := wg.Write(packets, 0)
				if err != nil || sentPacketCount != packetCount {
					benchmark.Fatalf("sent packets=%d/%d: %v", sentPacketCount, packetCount, err)
				}
			}
		})

		for _, packetBatchSize := range []int{1, 8, 64, 128} {
			benchmark.Run(
				fmt.Sprintf("grouped-batch-%d/packets-%d", packetBatchSize, packetCount),
				func(benchmark *testing.B) {
					tun := &benchmarkBatchCopyWgTun{}
					settings := DefaultWgProxySettings()
					settings.UploadPacketBatchSize = packetBatchSize
					wg := &WgProxy{
						ctx:           context.Background(),
						settings:      settings,
						receive:       make(chan []byte, 128),
						clients:       map[netip.Addr]*WgClient{},
						activeClients: map[netip.Addr]WgTun{clientAddr: tun},
					}

					benchmark.SetBytes(int64(packetByteCount))
					benchmark.ReportAllocs()
					benchmark.ResetTimer()
					for range benchmark.N {
						sentPacketCount, err := wg.Write(packets, 0)
						if err != nil || sentPacketCount != packetCount {
							benchmark.Fatalf("sent packets=%d/%d: %v", sentPacketCount, packetCount, err)
						}
					}
				},
			)
		}
	}
}

// Drains the same ready 128-packet workload at several bounds. No producer or
// coalescing wait is measured; only the number of userwireguard read crossings
// changes.
func BenchmarkWgProxyDownloadReadyDrain(benchmark *testing.B) {
	const packetCount = 128
	const packetByteCount = 1248
	packet := make([]byte, packetByteCount)
	for _, packetBatchSize := range []int{1, 8, 64, 128} {
		benchmark.Run(fmt.Sprintf("batch-%d", packetBatchSize), func(benchmark *testing.B) {
			settings := DefaultWgProxySettings()
			settings.DownloadPacketBatchSize = packetBatchSize
			wg := &WgProxy{
				ctx:      context.Background(),
				settings: settings,
				receive:  make(chan []byte, packetCount),
			}
			buffers := make([][]byte, packetBatchSize)
			for packetIndex := range buffers {
				buffers[packetIndex] = make([]byte, packetByteCount)
			}
			sizes := make([]int, packetBatchSize)

			benchmark.SetBytes(packetCount * packetByteCount)
			benchmark.ReportAllocs()
			benchmark.ReportMetric(float64(packetCount)/float64(packetBatchSize), "reads/op")
			for range benchmark.N {
				benchmark.StopTimer()
				for range packetCount {
					wg.receive <- packet
				}
				benchmark.StartTimer()

				readPacketCount := 0
				for readPacketCount < packetCount {
					count, err := wg.Read(buffers, sizes, 0)
					if err != nil {
						benchmark.Fatal(err)
					}
					readPacketCount += count
				}
			}
		})
	}
}
