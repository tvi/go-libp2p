package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	var reuseKey bool
	var serverName string
	flag.BoolVar(&reuseKey, "reuse-key", false, "")
	flag.StringVar(&serverName, "server-name", "", "")
	flag.Parse()
	if serverName == "" {
		panic("need servername")
	}
	serverName = strings.Trim(serverName, "\n\t ")
	pk, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		panic(err)
	}
	if reuseKey {
		pk = PrivKey(pk)
	}

	port := 5123
	listenAddrStrings := []string{
		fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", port),
		fmt.Sprintf("/ip4/0.0.0.0/udp/%d/webrtc-direct", port+1),
		fmt.Sprintf("/ip6/::/udp/%d/quic-v1", port),
		fmt.Sprintf("/ip6/::/udp/%d/webrtc-direct", port+1),
	}

	pLimit := rcmgr.PartialLimitConfig{
		System: rcmgr.ResourceLimits{
			Streams:         1000,
			StreamsInbound:  1000,
			StreamsOutbound: 1000,
			Conns:           10000,
			ConnsInbound:    5000,
			ConnsOutbound:   5000,
			FD:              1000,
			Memory:          1000_000_000,
		},
		Transient: rcmgr.ResourceLimits{
			Streams:         100,
			StreamsInbound:  100,
			StreamsOutbound: 100,
			Conns:           1000,
			ConnsInbound:    500,
			ConnsOutbound:   500,
			FD:              100,
			Memory:          100_000_000,
		},
	}
	cLimit := pLimit.Build(rcmgr.DefaultLimits.AutoScale())

	r, err := rcmgr.NewResourceManager(
		rcmgr.NewFixedLimiter(
			cLimit,
		),
	)
	if err != nil {
		panic(err)
	}

	h, err := libp2p.New(
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.Transport(libp2pwebrtc.New),
		libp2p.Identity(pk),
		libp2p.ListenAddrStrings(listenAddrStrings...),
		libp2p.EnableAutoNATv2(),
		libp2p.UDPBlackHoleSuccessCounter(nil),
		libp2p.IPv6BlackHoleSuccessCounter(nil),
		libp2p.ForceReachabilityPublic(),
		libp2p.DisableRelay(),
		libp2p.WithDialTimeout(10*time.Second),
		libp2p.ResourceManager(r),
		libp2p.AddrsFactory(func(addrs []ma.Multiaddr) []ma.Multiaddr {
			return []ma.Multiaddr{
				ma.StringCast(fmt.Sprintf("/dns/%s/udp/5123/quic-v1", serverName)),
				ma.StringCast(fmt.Sprintf("/dns/%s/udp/5124/webrtc-direct", serverName)),
			}
		}),
		libp2p.DisableIdentifyAddressDiscovery(),
	)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	d, err := dht.New(ctx, h,
		dht.BucketSize(20),
		dht.Concurrency(5),
		dht.RoutingTableRefreshPeriod(30*time.Minute),
		dht.Mode(dht.ModeServer),
		dht.BootstrapPeers(dht.GetDefaultBootstrapPeerAddrInfos()...),
	)
	if err != nil {
		panic(err)
	}
	for _, a := range h.Addrs() {
		fmt.Printf("%s/p2p/%s\n", a, h.ID())
	}
	go func() {
		if err := http.ListenAndServe(":5001", promhttp.Handler()); err != nil {
			panic(err)
		}
	}()
	d.Bootstrap(ctx)
	select {}
}

func PrivKey(pk crypto.PrivKey) crypto.PrivKey {
	f, err := os.OpenFile("priv.key", os.O_CREATE|os.O_RDWR, os.ModePerm)
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 1024)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if n == 0 {
		raw, err := pk.Raw()
		if err != nil {
			panic(err)
		}
		n := base32.StdEncoding.EncodedLen(len(raw))
		base32.StdEncoding.Encode(buf, raw)
		n, err = f.Write(buf[:n])
		if n == 0 || err != nil {
			panic(err)
		}
		f.Sync()
		f.Close()
		return pk
	}
	raw := make([]byte, 1024)
	n, err = base32.StdEncoding.Decode(raw, buf[:n])
	if err != nil {
		panic(err)
	}
	raw = raw[:n]
	pk, err = crypto.UnmarshalEd25519PrivateKey(raw)
	if err != nil {
		panic(err)
	}
	return pk
}
