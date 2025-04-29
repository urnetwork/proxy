module github.com/urnetwork/proxy/socks

go 1.24.0

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/golang/glog v1.2.4
	github.com/google/gopacket v1.1.19
	github.com/samber/lo v1.50.0
	github.com/things-go/go-socks5 v0.0.6
	github.com/urfave/cli/v2 v2.27.6
	github.com/urnetwork/connect v0.2.0
	golang.org/x/net v0.39.0
	gvisor.dev/gvisor v0.0.0-20250428193742-2d800c3129d5
)

require (
	github.com/google/btree v1.1.3 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/oklog/ulid/v2 v2.1.0 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/exp v0.0.0-20250408133849-7e4ce0ab07d0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	src.agwa.name/tlshacks v0.0.0-20231008131857-90d701ba3225 // indirect
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
)

replace github.com/urnetwork/connect => ../../connect
