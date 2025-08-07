module github.com/urnetwork/proxy/wg

go 1.24.4

toolchain go1.24.5

require (
	github.com/google/gopacket v1.1.19
	github.com/urnetwork/connect v0.0.0
	github.com/urnetwork/userwireguard v0.0.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
)

require (
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/golang/glog v1.2.5 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	github.com/quic-go/quic-go v0.53.0 // indirect
	go.uber.org/mock v0.5.2 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	golang.org/x/tools v0.34.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	src.agwa.name/tlshacks v0.0.0-20250628001001-c92050511ef4 // indirect
)

replace github.com/urnetwork/connect => ../../connect

replace github.com/urnetwork/userwireguard => ../../userwireguard
