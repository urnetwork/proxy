module github.com/urnetwork/proxy

go 1.25.5

require (
	github.com/elazarl/goproxy v1.7.2
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/google/gopacket v1.1.19
	github.com/google/uuid v1.6.0
	github.com/prometheus/client_golang v1.23.0
	github.com/redis/go-redis/v9 v9.12.0
	github.com/samber/lo v1.50.0
	github.com/things-go/go-socks5 v0.0.6
	github.com/urfave/cli/v2 v2.27.7
	github.com/urnetwork/connect v0.0.0
	github.com/urnetwork/glog v0.0.0
	github.com/urnetwork/userwireguard v0.0.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	gvisor.dev/gvisor v0.0.0-20260109181451-4be7c433dae2
)

require (
	github.com/google/btree v1.1.3 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/exp v0.0.0-20251219203646-944ab1f22d93 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	src.agwa.name/tlshacks v0.0.2 // indirect
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.65.0 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/quic-go/quic-go v0.58.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/stripe/goproxy v0.0.0-20251009123132-ee3e713dae03 // indirect
	github.com/xrash/smetrics v0.0.0-20250705151800-55b8f293f342 // indirect
	golang.org/x/net v0.48.0 // indirect
)

replace github.com/urnetwork/connect => ../connect

replace github.com/urnetwork/glog => ../glog

replace github.com/urnetwork/userwireguard => ../userwireguard
