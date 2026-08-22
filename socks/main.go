package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	// "net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/docopt/docopt-go"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/proxy"
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
		addr           string
		network        string
		apiURL         string
		platformURL    string
		userAuth       string
		password       string
		authCode       string
		jwt            string
		providerID     string
		city           string
		country        string
		region         string
		metricsEveryMs int
		resetMetrics   bool
		reliability    string
		control        string
	}{}
	usage := `socksproxy - dev socks5 proxy over urnetwork.

Usage:
    socksproxy [options]

Options:
    --addr=<addr>                  socks5 server address (env ADDR, default 127.0.0.1:9999)
    --network=<network>            preset endpoints: main or beta (env NETWORK, default main)
    --api-url=<api-url>            api url (env API_URL, default from --network)
    --platform-url=<platform-url>  platform url (env PLATFORM_URL, default from --network)
    --user-auth=<user-auth>        user auth (env USER_AUTH)
    --password=<password>          password (env PASSWORD)
    --auth-code=<auth-code>        auth code login (env AUTH_CODE) — preferred for beta/test networks
    --jwt=<jwt>                    existing network jwt (env JWT), skips login entirely
    --provider-id=<provider-id>    provider id (env PROVIDER_ID)
    --city=<city>                  city (env CITY)
    --country=<country>            country (env COUNTRY)
    --region=<region>              region (env REGION)
    --metrics-every=<ms>           print reliability metrics + exit table every N ms (env METRICS_EVERY, 0 = off)
    --reset-metrics                zero the reliability counters at startup (env RESET_METRICS=1)
    --reliability=<file>           json file of reliability settings applied at startup (env RELIABILITY)
    --control=<addr>               local control http server (env CONTROL, e.g. 127.0.0.1:9998, empty = off)
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
	cfg.addr = pick("--addr", "ADDR", "127.0.0.1:9999")
	cfg.network = pick("--network", "NETWORK", "main")
	switch cfg.network {
	case "main":
		cfg.apiURL = pick("--api-url", "API_URL", "https://api.bringyour.com")
		cfg.platformURL = pick("--platform-url", "PLATFORM_URL", "wss://connect.bringyour.com")
	case "beta":
		cfg.apiURL = pick("--api-url", "API_URL", "https://api.beta-test.net")
		cfg.platformURL = pick("--platform-url", "PLATFORM_URL", "wss://connect.beta-test.net")
	default:
		fmt.Fprintf(os.Stderr, "unknown --network %q: expected main or beta\n", cfg.network)
		os.Exit(1)
	}
	// explicit --api-url / --platform-url still override the preset, and the
	// env vars follow -- pick() above already gave flags priority over env
	cfg.userAuth = pick("--user-auth", "USER_AUTH", "")
	cfg.password = pick("--password", "PASSWORD", "")
	cfg.authCode = pick("--auth-code", "AUTH_CODE", "")
	cfg.jwt = pick("--jwt", "JWT", "")
	cfg.providerID = pick("--provider-id", "PROVIDER_ID", "")
	cfg.city = pick("--city", "CITY", "")
	cfg.country = pick("--country", "COUNTRY", "")
	cfg.region = pick("--region", "REGION", "")

	if v := optStr("--metrics-every"); v != "" {
		ms, err := strconv.Atoi(v)
		if err != nil || ms <= 0 {
			fmt.Fprintln(os.Stderr, "--metrics-every must be a positive millisecond value")
			os.Exit(1)
		}
		cfg.metricsEveryMs = ms
	} else if v := os.Getenv("METRICS_EVERY"); v != "" {
		ms, err := strconv.Atoi(v)
		if err != nil || ms <= 0 {
			fmt.Fprintln(os.Stderr, "--metrics-every must be a positive millisecond value")
			os.Exit(1)
		}
		cfg.metricsEveryMs = ms
	}
	resetMetrics, _ := opts.Bool("--reset-metrics")
	cfg.resetMetrics = resetMetrics || os.Getenv("RESET_METRICS") == "1"
	cfg.reliability = pick("--reliability", "RELIABILITY", "")
	cfg.control = pick("--control", "CONTROL", "")

	if cfg.jwt == "" && cfg.authCode == "" && (cfg.userAuth == "" || cfg.password == "") {
		fmt.Fprintln(os.Stderr, "provide --jwt, --auth-code, or --user-auth + --password (or set JWT / AUTH_CODE / USER_AUTH + PASSWORD)")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	run := func() error {

		var jwt string
		var err error
		switch {
		case cfg.jwt != "":
			jwt = cfg.jwt
		case cfg.authCode != "":
			jwt, err = loginWithAuthCode(ctx, cfg.apiURL, cfg.authCode)
		default:
			jwt, err = login(ctx, cfg.apiURL, cfg.userAuth, cfg.password)
		}
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

		if cfg.reliability != "" {
			// merge over the current (default) settings so unspecified fields
			// keep their defaults instead of being zeroed
			f, err := parseReliabilityFile(cfg.reliability)
			if err != nil {
				return fmt.Errorf("reliability settings: %w", err)
			}
			merged := settingsToFile(mc.ReliabilitySettings())
			if err := applyFileOver(merged, f); err != nil {
				return fmt.Errorf("reliability settings: %w", err)
			}
			settings, err := fileToSettings(merged)
			if err != nil {
				return fmt.Errorf("reliability settings: %w", err)
			}
			mc.SetReliabilitySettings(settings)
			fmt.Printf("reliability settings loaded from %s\n", cfg.reliability)
		}

		if cfg.control != "" {
			// the control server is unauthenticated and can change settings,
			// drop exits, and migrate flows -- refuse non-loopback binds
			ok, err := controlAddrIsLoopback(cfg.control)
			if err != nil {
				return fmt.Errorf("control address: %w", err)
			}
			if !ok {
				return fmt.Errorf("control address %q must be loopback; the control server is unauthenticated", cfg.control)
			}
			server, err := newControlServer(cfg.control, mc)
			if err != nil {
				return fmt.Errorf("control server: %w", err)
			}
			server.SetCancel(stop)
			go server.serve(ctx)
			fmt.Printf("control server listening on %s\n", cfg.control)
		}

		if cfg.resetMetrics {
			mc.ResetReliabilityMetrics()
			fmt.Println("reliability metrics reset")
		}

		if cfg.metricsEveryMs > 0 {
			go func() {
				ticker := time.NewTicker(time.Duration(cfg.metricsEveryMs) * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						printReliabilityMetrics(mc)
					}
				}
			}()
			fmt.Printf("reliability metrics every %dms\n", cfg.metricsEveryMs)
		}

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
		socksProxy.ConnectDialWithRequest = func(ctx context.Context, r proxy.SocksRequest, network string, addr string) (net.Conn, error) {
			fmt.Println("Dialing", network, addr, r.DestAddr.FQDN)
			return dev.DialContext(ctx, network, addr)
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- socksProxy.ListenAndServe(ctx, "tcp", cfg.addr)
		}()

		fmt.Printf("socks5 server is listening on %s\n", cfg.addr)

		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return err
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// printReliabilityMetrics writes the reliability counters and the current
// exit table to stdout. It is the console equivalent of the android
// developer screen's measurements block: flows opened, dial failures
// intercepted/reraced, blast radius (mean + worst exit loss), recovery
// mean/max/pending, probes sent/answered/qualified, busy probes, verdicts
// held, removals deferred, rebinds, and one row per exit (warning /
// quarantine flags, flow count, dial failures, tier vs effective tier,
// proven status). Called on the --metrics-every ticker.
func printReliabilityMetrics(mc mcControl) {
	m := mc.ReliabilityMetrics()
	if m == nil {
		return
	}
	fmt.Printf("\n--- reliability metrics %s ---\n", time.Now().Format("15:04:05"))
	fmt.Printf("flows_opened=%d dial_failures_intercepted=%d flows_reraced=%d\n", m.FlowsOpened, m.DialFailuresIntercepted, m.FlowsReraced)
	fmt.Printf("exit_loss_events=%d flows_lost_to_exit=%d max_flows_lost_one_event=%d mean_flows_lost_per_exit_loss=%.2f\n",
		m.ExitLossEvents, m.FlowsLostToExit, m.MaxFlowsLostInOneEvent, m.MeanFlowsLostPerExitLoss)
	fmt.Printf("recovery_count=%d recovery_missed=%d recovery_mean=%s recovery_max=%s recovery_pending=%d\n",
		m.RecoveryCount, m.RecoveryMissed, fmtDurationMillis(m.RecoveryMeanNanos/1e6), fmtDurationMillis(m.RecoveryMaxNanos/1e6), m.RecoveryPending)
	fmt.Printf("probes_sent=%d probes_answered=%d providers_qualified=%d busy_probes_sent=%d busy_probes_acquitted=%d scheduler_pauses=%d\n",
		m.ProbesSent, m.ProbesAnswered, m.ProvidersQualified, m.BusyProbesSent, m.BusyProbesAcquitted, m.SchedulerPausesDetected)
	fmt.Printf("verdicts_held_uplink_stale=%d verdicts_held_transport_down=%d removals_deferred=%d\n",
		m.VerdictsHeldUplinkStale, m.VerdictsHeldTransportDown, m.RemovalsDeferred)
	fmt.Printf("flows_rebound=%d rebinds_accepted=%d rebinds_redialed=%d groups_followed=%d groups_scattered=%d\n",
		m.FlowsRebound, m.RebindsAccepted, m.RebindsRedialed, m.GroupsFollowed, m.GroupsScattered)

	exits := mc.Exits()
	if len(exits) == 0 {
		fmt.Println("exits: none")
		return
	}
	fmt.Println("exits:")
	for _, e := range exits {
		flags := ""
		if e.Warning {
			flags += "W"
		}
		if e.Quarantined {
			flags += "Q"
		}
		if e.Done {
			flags += "D"
		}
		if flags == "" {
			flags = "-"
		}
		fmt.Printf("  %s %s flows=%d dial_failures=%d tier=%d effective_tier=%d proven=%v\n",
			flags, exitLabel(e.ClientId), e.FlowCount, e.DialFailureCount, e.Tier, e.EffectiveTier, e.Proven)
	}
}

// fmtDurationMillis renders a millisecond duration compactly: raw ms below a
// second, one-decimal seconds above. Negative values (an unset clock) render
// as "-" so "never measured" reads differently from "0ms".
func fmtDurationMillis(ms int64) string {
	if ms < 0 {
		return "-"
	}
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000.0)
}

// exitLabel renders a short suffix of the client id so rows are
// distinguishable. Client ids are ULIDs -- the leading characters encode
// creation time, so channels opened milliseconds apart look identical; the
// random component is in the tail.
func exitLabel(id connect.Id) string {
	return exitLabelString(id.String())
}

func exitLabelString(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[len(s)-8:]
}

// controlAddrIsLoopback reports whether addr is a loopback bind address
// (localhost, 127.0.0.1, or ::1) with a port. The control server is
// unauthenticated, so anything else must be refused.
func controlAddrIsLoopback(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, err
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return false, nil
	}
	return true, nil
}

// getProviderSpec resolves the provider-locations result to a ProviderSpec
// by, in order: exact provider id, city, country, region. The matching is
// case-insensitive. An unmatched location yields a help listing of every
// country/region/city available.
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

// loginWithAuthCode redeems an auth code via POST /auth/code-login and
// returns the network by_jwt. This is the auth path for beta/test networks
// that have no password accounts -- the same flow the provider CLI uses.
func loginWithAuthCode(ctx context.Context, apiURL, authCode string) (string, error) {
	api := connect.NewBringYourApi(
		ctx,
		connect.NewClientStrategyWithDefaults(ctx),
		apiURL,
	)

	res, err := api.AuthCodeLoginSync(&connect.AuthCodeLoginArgs{
		AuthCode: authCode,
	})
	if err != nil {
		return "", err
	}
	if res.Error != nil {
		return "", errors.New(res.Error.Message)
	}

	return res.ByJwt, nil
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

// parseByJwtClientId extracts the client_id claim from a by_jwt token without
// verifying its signature (the network already authenticated the token).
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
