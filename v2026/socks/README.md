# SOCKS5 Proxy Frontend for VPN

This project provides a SOCKS5 proxy server that routes all network connections through our VPN service. By running this proxy locally, you can configure your system or applications to use it, ensuring all your traffic is securely tunneled through the VPN.

## Features

- SOCKS5 proxy server implementation with VPN integration
- Support for both IPv4 and IPv6 traffic
- Flexible location selection (country, region, city)
- Provider-specific routing options
- Built-in DNS resolution through the VPN tunnel
- TCP and UDP protocol support
- Secure authentication system

## Usage

Run the proxy server with the following command:

```bash
go run . --user-auth <your-auth> --password <your-password> --country "United States"
```

Replace `<your-auth>` and `<your-password>` with your VPN authentication details.

### Command-Line Options

- `--user-auth`: Your VPN user auth.
- `--password`: Your VPN password.
- `--country`: *(Optional)* Country to connect to (e.g., "United States").
- `--region`: *(Optional)* Region within the country.
- `--city`: *(Optional)* Specific city to connect through.
- `--provider-id`: *(Optional)* Specific provider ID to connect to.
- `--addr`: *(Optional)* Bind address for the proxy server (default is `127.0.0.1:9999`, loopback only). A non-loopback address requires `--socks-user` and `--socks-password`. See [Using the proxy from containers or other hosts](#using-the-proxy-from-containers-or-other-hosts).
- `--socks-user`, `--socks-password`: *(Optional)* SOCKS5 username and password clients must send. Required when `--addr` is not a loopback address.
- `--api-url`: *(Optional)* Custom API URL (default is `https://api.bringyour.com`).
- `--platform-url`: *(Optional)* Custom platform URL (default is `wss://connect.bringyour.com`).

Each option can also be set with an environment variable: `ADDR`, `USER_AUTH`, `PASSWORD`, `PROVIDER_ID`, `CITY`, `COUNTRY`, `REGION`, `SOCKS_USER`, `SOCKS_PASSWORD`, `API_URL`, `PLATFORM_URL`.

### Example: Connecting via Provider ID

To connect to a specific provider, use the `--provider-id` flag:

```bash
go run . --user-auth <your-auth> --password <your-password> --provider-id <provider-id>
```

## Configuring Your System Proxy

After starting the proxy server:

1. Go to your system's network settings.
2. Set the SOCKS5 proxy to `localhost` and port `9999` (or your custom port if specified).
3. Save the settings.

All your network traffic will now be routed through the VPN via the proxy.

## Using the proxy from containers or other hosts

By default the proxy listens on `127.0.0.1:9999`, which is reachable only from
the same network namespace. Inside a Docker container `127.0.0.1` is the
container's own loopback, not the host, so a client such as tun2proxy or
tun2socks started with `--proxy socks5://127.0.0.1:9999` in its own container
gets `Connection refused (os error 111)` and the proxy logs nothing.

To use the proxy from another container or host, either:

- share the host network with the client container, e.g.
  `docker run --network host ... ghcr.io/tun2proxy/tun2proxy-ubuntu:latest --proxy socks5://127.0.0.1:9999`, or
- bind the proxy to a reachable address with SOCKS5 credentials and point the
  client at the host's address on that network, e.g.
  `--addr 172.17.0.1:9999 --socks-user <user> --socks-password <pass>` and
  `--proxy socks5://<user>:<pass>@172.17.0.1:9999` (172.17.0.1 is the default
  Docker bridge gateway).

The proxy refuses to start on a non-loopback `--addr` unless `--socks-user`
and `--socks-password` (or `SOCKS_USER` / `SOCKS_PASSWORD`) are set, so an
unauthenticated port is never exposed to the network. Prefer binding to a
specific trusted interface over `0.0.0.0`.

UDP (for example DNS through tun2proxy) uses SOCKS5 UDP ASSOCIATE. The UDP
relay is opened on the same local address the client connected to, so it is
reachable wherever the TCP port is.

## Technical Details

The proxy server:
- Uses a custom network stack for handling traffic
- Implements full SOCKS5 protocol specification
- Provides transparent DNS resolution through the VPN tunnel
- Supports both TCP and UDP protocols
- Handles IPv4 and IPv6 connections
- Maintains persistent VPN connections
- Provides automatic reconnection on network changes

## Requirements

- Go 1.23 or later
- Network connectivity to VPN servers
- Valid VPN authentication credentials

