/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/urnetwork/userwireguard/conn"
	"github.com/urnetwork/userwireguard/device"
	"github.com/urnetwork/userwireguard/logger"
	uwgtun "github.com/urnetwork/userwireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	// set logger to wanted log level (available - LogLevelVerbose, LogLevelError, LogLevelSilent)
	logLevel := logger.LogLevelVerbose // verbose/debug logging
	logger := logger.NewLogger(logLevel, "")

	// public IP addresses (change these to server's public IP addresses)
	var publicIPv4 net.IP = net.IPv4(1, 2, 3, 4)
	var publicIPv6 net.IP = nil

	// tun device
	utun, err := CreateUserspaceTUN(logger, &publicIPv4, &publicIPv6)
	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(1)
	}

	// wireguard device
	device := device.NewDevice(utun, conn.NewDefaultBind(), logger)
	logger.Verbosef("Device started")

	// keys (change these)
	privateKeyServer := "__PLACEHOLDER__"
	publicKeyPeer := "__PLACEHOLDER__"

	privServer, err := wgtypes.ParseKey(privateKeyServer)
	if err != nil {
		logger.Errorf("Invalid server private key provided: %w", err)
		os.Exit(1)
	}

	pubPeer, err := wgtypes.ParseKey(publicKeyPeer)
	if err != nil {
		logger.Errorf("Invalid peer public key provided: %w", err)
		os.Exit(1)
	}

	port := 33336

	// ipcSet (set configuration)
	config := wgtypes.Config{
		PrivateKey:   &privServer,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         pubPeer,
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{
					{
						IP:   net.IPv4(192, 168, 90, 1),
						Mask: net.CIDRMask(32, 32),
					},
				},
			},
		},
	}

	if err := device.IpcSet(&config); err != nil {
		logger.Errorf("Failed to Set Config: %v", err)
		os.Exit(1)
	}

	term := make(chan os.Signal, 1) // channel for termination

	device.AddEvent(uwgtun.EventUp) // start up the device

	// wait for program to terminate
	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-device.Wait():
	}

	// clean up
	device.Close()
}
