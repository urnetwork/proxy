module github.com/urnetwork/proxy/http

go 1.24.6

require (
	github.com/elazarl/goproxy v1.7.2
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/golang/glog v1.2.5
	github.com/google/gopacket v1.1.19
	github.com/google/uuid v1.6.0
	github.com/miekg/dns v1.1.68
	github.com/prometheus/client_golang v1.23.0
	github.com/redis/go-redis/v9 v9.12.0
	github.com/stretchr/testify v1.10.0
	github.com/urfave/cli/v2 v2.27.7
	github.com/urnetwork/connect v0.0.0
	golang.org/x/sync v0.16.0
	gvisor.dev/gvisor v0.0.0-20241009022347-94b16c128c1c
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.65.0 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/quic-go/quic-go v0.54.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20250705151800-55b8f293f342 // indirect
	go.uber.org/mock v0.5.2 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/exp v0.0.0-20250808145144-a408d31f581a // indirect
	golang.org/x/mod v0.27.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	golang.org/x/tools v0.36.0 // indirect
	google.golang.org/protobuf v1.36.7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	src.agwa.name/tlshacks v0.0.0-20250628001001-c92050511ef4 // indirect
)

replace github.com/urnetwork/connect => ../../connect
