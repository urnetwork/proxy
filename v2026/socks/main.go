package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	// "net/netip"
	"flag"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/docopt/docopt-go"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/urnetwork/connect/v2026"
	"github.com/urnetwork/connect/v2026/protocol"
	"github.com/urnetwork/proxy/v2026"
)

// this value is set via the linker, e.g.
// -ldflags "-X main.Version=$WARP_VERSION-$WARP_VERSION_CODE"
var Version string

func init() {
	initGlog()
}

func initGlog() {
	// flag.Set("logtostderr", "true")
	flag.Set("alsologtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Set("v", "0")
	// unlike unix, the android/ios standard is for diagnostics to go to stdout
	os.Stderr = os.Stdout
}

func main() {
	cfg := struct {
		addr        string
		apiURL      string
		platformURL string
		userAuth    string
		password    string
		providerID  string
		city        string
		country     string
		region      string
	}{}
	usage := `socksproxy - dev socks5 proxy over urnetwork.

Usage:
    socksproxy [options]

Options:
    --addr=<addr>                  socks5 server address (env ADDR, default :9999)
    --api-url=<api-url>            api url (env API_URL, default https://api.bringyour.com)
    --platform-url=<platform-url>  platform url (env PLATFORM_URL, default wss://connect.bringyour.com)
    --user-auth=<user-auth>        user auth, required (env USER_AUTH)
    --password=<password>          password, required (env PASSWORD)
    --provider-id=<provider-id>    provider id (env PROVIDER_ID)
    --city=<city>                  city (env CITY)
    --country=<country>            country (env COUNTRY)
    --region=<region>              region (env REGION)
    -h --help                      show this help.`

	opts, err := docopt.ParseArgs(usage, os.Args[1:], Version)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// a flag value, or its env var fallback, or the hardcoded default -- matches
	// the previous cli EnvVars/Value behavior. docopt has no native env support.
	optStr := func(name string) string {
		if s, ok := opts[name].(string); ok {
			return s
		}
		return ""
	}
	pick := func(optName string, envName string, def string) string {
		if v := optStr(optName); v != "" {
			return v
		}
		if v := os.Getenv(envName); v != "" {
			return v
		}
		return def
	}
	cfg.addr = pick("--addr", "ADDR", ":9999")
	cfg.apiURL = pick("--api-url", "API_URL", "https://api.bringyour.com")
	cfg.platformURL = pick("--platform-url", "PLATFORM_URL", "wss://connect.bringyour.com")
	cfg.userAuth = pick("--user-auth", "USER_AUTH", "")
	cfg.password = pick("--password", "PASSWORD", "")
	cfg.providerID = pick("--provider-id", "PROVIDER_ID", "")
	cfg.city = pick("--city", "CITY", "")
	cfg.country = pick("--country", "COUNTRY", "")
	cfg.region = pick("--region", "REGION", "")
	if cfg.userAuth == "" || cfg.password == "" {
		fmt.Fprintln(os.Stderr, "--user-auth and --password are required (or set USER_AUTH / PASSWORD)")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	run := func() error {

		jwt, err := login(ctx, cfg.apiURL, cfg.userAuth, cfg.password)
		if err != nil {
			return fmt.Errorf("login failed: %w", err)
		}

		locations, err := getProviderLocations(
			ctx,
			cfg.apiURL,
			jwt,
		)
		if err != nil {
			return fmt.Errorf("get locations failed: %w", err)
		}

		providersSpec, err := getProviderSpec(
			locations,
			cfg.city,
			cfg.country,
			cfg.region,
			cfg.providerID,
		)
		if err != nil {
			return fmt.Errorf("get provider spec failed: %w", err)
		}

		clientJWT, err := authNetworkClient(
			ctx,
			cfg.apiURL,
			jwt,
			&connect.AuthNetworkClientArgs{
				Description: "my device",
				DeviceSpec:  "socks5",
			},
		)

		if err != nil {
			return fmt.Errorf("auth network client failed: %w", err)
		}

		clientID, err := parseByJwtClientId(clientJWT)
		if err != nil {
			return fmt.Errorf("parse byJwt client id failed: %w", err)
		}

		fmt.Println("my clientID:", clientID)

		generator := connect.NewApiMultiClientGenerator(
			ctx,
			providersSpec,
			connect.NewClientStrategyWithDefaults(ctx),
			// exclude self
			[]connect.Id{
				clientID,
			},
			cfg.apiURL,
			clientJWT,
			cfg.platformURL,
			"my device",
			"socks5",
			"0.0.0",
			&clientID,
			// connect.DefaultClientSettingsNoNetworkEvents,
			connect.DefaultClientSettings,
			connect.DefaultApiMultiClientGeneratorSettings(),
		)

		dev, err := connect.CreateTunWithDefaults(ctx)
		if err != nil {
			return fmt.Errorf("create net tun failed: %w", err)
		}

		mc := connect.NewRemoteUserNatMultiClientWithDefaults(
			ctx,
			generator,
			func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
				_, err := dev.Write(packet)
				if err != nil {
					fmt.Println("packet write error:", err)
				}
			},
			protocol.ProvideMode_Network,
		)

		source := connect.SourceId(clientID)

		go func() {
			for {
				packet, err := dev.Read()
				if err == nil {
					mc.SendPacket(
						source,
						protocol.ProvideMode_Network,
						packet,
						time.Second*15,
					)
				}
				if err != nil {
					fmt.Println("read error:", err)
					return
				}
			}
		}()

		socksProxy := proxy.NewSocksProxyWithDefaults()
		// a dev tool: any credentials are accepted
		socksProxy.ValidUser = func(user string, password string, userAddr string) bool {
			return true
		}
		socksProxy.ConnectDialWithRequest = func(ctx context.Context, r proxy.SocksRequest, network string, addr string) (net.Conn, error) {
			fmt.Println("Dialing", network, addr, r.DestAddr.FQDN)
			return dev.DialContext(ctx, network, addr)
		}

		go socksProxy.ListenAndServe(ctx, "tcp", cfg.addr)

		fmt.Printf("socks5 server is listening on %s\n", cfg.addr)

		<-ctx.Done()

		return nil
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func getProviderSpec(
	locations *FindLocationsResult,
	city string,
	country string,
	region string,
	providerID string,
) ([]*connect.ProviderSpec, error) {

	if providerID != "" {
		cid, err := connect.ParseId(providerID)
		if err != nil {
			return nil, fmt.Errorf("parse provider id failed: %w", err)
		}

		fmt.Println("provider match", cid)

		return []*connect.ProviderSpec{
			{
				ClientId: &cid,
			},
		}, nil
	}

	if city != "" {
		for _, v := range locations.Locations.Values() {

			switch v.LocationType {
			case "city":
				if strings.ToLower(v.Name) == strings.ToLower(city) {
					fmt.Printf("city matched %q, provider count %d\n", v.Name, v.ProviderCount)
					return []*connect.ProviderSpec{
						{
							LocationId: v.LocationId,
						},
					}, nil
				}
			}

		}
	}

	if country != "" {

		for _, v := range locations.Locations.Values() {

			switch v.LocationType {
			case "country":
				if strings.ToLower(v.Name) == strings.ToLower(country) {
					fmt.Printf("country matched %q, provider count %d\n", v.Name, v.ProviderCount)
					return []*connect.ProviderSpec{
						{
							LocationId: v.LocationId,
						},
					}, nil
				}
			}

		}
	}

	if region != "" {

		for _, v := range locations.Locations.Values() {

			switch v.LocationType {
			case "region":
				if strings.ToLower(v.Name) == strings.ToLower(region) {
					fmt.Printf("region matched %q, provider count %d\n", v.Name, v.ProviderCount)
					return []*connect.ProviderSpec{
						{
							LocationId: v.LocationId,
						},
					}, nil
				}
			}

		}
	}

	regions := filter(locations.Locations.Values(), func(v *LocationResult) bool {
		return v.LocationType == "region"
	})

	cities := filter(locations.Locations.Values(), func(v *LocationResult) bool {
		return v.LocationType == "city"
	})

	countries := filter(locations.Locations.Values(), func(v *LocationResult) bool {
		return v.LocationType == "country"
	})

	uniqNames := func(locations []*LocationResult) []string {
		names := mapSlice(locations, func(v *LocationResult) string {
			return v.Name
		})
		slices.Sort(names)
		return slices.Compact(names)
	}

	prefixEach := func(prefix string, names []string) []string {
		return mapSlice(names, func(v string) string {
			return prefix + v
		})
	}

	return nil, fmt.Errorf(
		`please specify a location: city, country, region or provider id from this list:
 countries:
%s
 regions:
%s
 cities:
%s`,
		strings.Join(prefixEach("  ", uniqNames(countries)), "\n"),
		strings.Join(prefixEach("  ", uniqNames(regions)), "\n"),
		strings.Join(prefixEach("  ", uniqNames(cities)), "\n"),
	)

}

func login(ctx context.Context, apiURL, userAuth, password string) (string, error) {
	api := connect.NewBringYourApi(
		ctx,
		connect.NewClientStrategyWithDefaults(ctx),
		apiURL,
	)

	// api.AuthNetworkClient()
	type loginResult struct {
		res *connect.AuthLoginWithPasswordResult
		err error
	}

	resChan := make(chan loginResult)

	api.AuthLoginWithPassword(
		&connect.AuthLoginWithPasswordArgs{
			UserAuth: userAuth,
			Password: password,
		},
		connect.NewApiCallback(
			func(res *connect.AuthLoginWithPasswordResult, err error) {
				resChan <- loginResult{res, err}
			},
		),
	)

	res := <-resChan
	if res.err != nil {
		return "", res.err
	}
	if res.res.Error != nil {
		return "", errors.New(res.res.Error.Message)
	}

	if res.res.VerificationRequired != nil {
		return "", errors.New("verification required")
	}

	return res.res.Network.ByJwt, nil

}

func getProviderLocations(ctx context.Context, apiURL string, jwt string) (*FindLocationsResult, error) {

	strategy := connect.NewClientStrategyWithDefaults(ctx)

	return connect.HttpGetWithStrategy(
		ctx,
		strategy,
		fmt.Sprintf("%s/network/provider-locations", apiURL),
		jwt,
		&FindLocationsResult{},
		connect.NewNoopApiCallback[*FindLocationsResult](),
	)

}

// func (self *BringYourApi) FindProviders(findProviders *FindProvidersArgs, callback FindProvidersCallback) {
// 	go connect.HandleError(func() {
// 		connect.HttpPostWithStrategy(
// 			self.ctx,
// 			self.clientStrategy,
// 			fmt.Sprintf("%s/network/find-providers", self.apiUrl),
// 			findProviders,
// 			self.GetByJwt(),
// 			&FindProvidersResult{},
// 			callback,
// 		)
// 	})
// }

func findProviders(ctx context.Context, apiURL string, jwt string, args *FindProvidersArgs) (*FindProvidersResult, error) {
	strategy := connect.NewClientStrategyWithDefaults(ctx)

	return connect.HttpPostWithStrategy(
		ctx,
		strategy,
		fmt.Sprintf("%s/network/find-providers", apiURL),
		args,
		jwt,
		&FindProvidersResult{},
		connect.NewNoopApiCallback[*FindProvidersResult](),
	)
}

func authNetworkClient(ctx context.Context, apiURL, jwt string, req *connect.AuthNetworkClientArgs) (string, error) {
	strategy := connect.NewClientStrategyWithDefaults(ctx)

	res, err := connect.HttpPostWithStrategy(
		ctx,
		strategy,
		fmt.Sprintf("%s/network/auth-client", apiURL),
		req,
		jwt,
		&connect.AuthNetworkClientResult{},
		connect.NewNoopApiCallback[*connect.AuthNetworkClientResult](),
	)

	if err != nil {
		return "", err
	}

	if res.Error != nil {
		return "", errors.New(res.Error.Message)
	}

	return res.ByClientJwt, nil
}

func parseByJwtClientId(byJwt string) (connect.Id, error) {
	claims := gojwt.MapClaims{}
	gojwt.NewParser().ParseUnverified(byJwt, claims)

	jwtClientId, ok := claims["client_id"]
	if !ok {
		return connect.Id{}, fmt.Errorf("byJwt does not contain claim client_id")
	}
	switch v := jwtClientId.(type) {
	case string:
		return connect.ParseId(v)
	default:
		return connect.Id{}, fmt.Errorf("byJwt hav invalid type for client_id: %T", v)
	}
}

// filter returns the elements of s for which keep returns true, in order.
func filter[T any](s []T, keep func(T) bool) []T {
	result := make([]T, 0, len(s))
	for _, v := range s {
		if keep(v) {
			result = append(result, v)
		}
	}
	return result
}

// mapSlice returns a new slice with f applied to each element of s.
func mapSlice[T any, R any](s []T, f func(T) R) []R {
	result := make([]R, len(s))
	for i, v := range s {
		result[i] = f(v)
	}
	return result
}
