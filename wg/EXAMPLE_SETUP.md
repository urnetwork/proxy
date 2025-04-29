For the setup you'll need two keypairs - one for the server (running userspace-wireguard) and one for the peer (running any wireguard distribution). You can get them using either `tetherctl`, any wireguard app or if you want here are some pairs:

**It is important that you server has an IP that is not behind a CGNAT, so an actual public IP, as that is the only way that the peer can contact it.**

For the peer, you can use any WireGuard distribution. Then, your config for the peer should look like this (replace the placeholders with the actual values):
```
[Interface]
PrivateKey = <peer-private-key>
Address = 192.168.90.1/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server-public-key>
AllowedIPs = 0.0.0.0/0
Endpoint = <server-public-ip>:33336
```

Then, assuming you have setup the above config with the correct values on the peer, you can go back to `main.go`. First, you need to change the `publicIPv4` and `publicIPv6` to have the corresponding IPs of the server. If the server does not have a public IPv6 then you can leave the variable to nil. These values should correspond with the `server-public-ip` in the peer config. Then, you need to change `privateKeyServer` and `publicKeyPeer` with the appropriate keys. And now run `main.go` and then after its running, the tunnel can be activated from the peer.

Currently, the logger is set to show debug info. You can change it to `logger.LogLevelError` if you don't wanna see debug info.