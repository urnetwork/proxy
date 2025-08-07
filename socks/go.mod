module github.com/urnetwork/proxy/socks

go 1.24.4

toolchain go1.24.5

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/golang/glog v1.2.5
	github.com/google/gopacket v1.1.19
	github.com/samber/lo v1.50.0
	github.com/things-go/go-socks5 v0.0.6
	github.com/urfave/cli/v2 v2.27.6
	github.com/urnetwork/connect v0.0.0
	golang.org/x/net v0.41.0
	gvisor.dev/gvisor v0.0.0-20250428193742-2d800c3129d5
)

require (
	github.com/google/btree v1.1.3 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	src.agwa.name/tlshacks v0.0.0-20250628001001-c92050511ef4 // indirect
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/quic-go/quic-go v0.53.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	go.uber.org/mock v0.5.2 // indirect
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/tools v0.34.0 // indirect
)

replace github.com/urnetwork/connect => ../../connect
