# URNetwork Proxy

A collection of user-space proxy implementations to bridge URNetwork to other protocols without requiring root privileges.

## Overview

The `proxy` repository provides two implementations:

- **socks**  
  A SOCKS5 proxy that routes traffic through URNetwork.

- **wg**  
  A WireGuard-based proxy for secure tunneling over URNetwork.

## Prerequisites

Before you begin, ensure you have:
   ```bash
   - Go and Git installed on your system.
   ```

## Installation

1. Clone the required repositories:
    ```bash
   git clone https://github.com/urnetwork/connect
   git clone https://github.com/urnetwork/proxy
   ```

2. Change into the proxy directory:
   ```bash
   cd proxy
   ```

3. Choose your implementation:
   
   ```bash
   # For the SOCKS5 proxy:
   cd socks

   # For the WireGuard proxy:
   cd wg
   ```

4. (Optional) Tidy up your module dependencies:
   ```bash
   go mod tidy
   ```

5. Configuration & Usage
   ```bash
   - `socks` Follow the steps in socks/README.md to configure and launch the SOCKS5 proxy.
   - `wg`    See wg/EXAMPLE_SETUP.md for an example WireGuard setup and usage instructions.
   ```
