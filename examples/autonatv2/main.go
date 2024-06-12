package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base32"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/autonatv2"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	libp2pwebtransport "github.com/libp2p/go-libp2p/p2p/transport/webtransport"
	manet "github.com/multiformats/go-multiaddr/net"
)

func main() {
	var port int
	var autonatServer string
	var reuseKey bool
	flag.StringVar(&autonatServer, "autonat-server", "", "")
	flag.IntVar(&port, "port", 4001, "")
	flag.BoolVar(&reuseKey, "reuse-key", false, "")
	flag.Parse()

	pk, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		panic(err)
	}
	if reuseKey {
		pk = PrivKey(pk)
	}
	listenAddrStrings := []string{
		fmt.Sprintf("/ip4/0.0.0.0/tcp/%d/", port),
		fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", port),
		fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1/webtransport", port),
		fmt.Sprintf("/ip4/0.0.0.0/udp/%d/webrtc-direct", port+1),
		fmt.Sprintf("/ip6/::/tcp/%d/", port),
		fmt.Sprintf("/ip6/::/udp/%d/quic-v1", port),
		fmt.Sprintf("/ip6/::/udp/%d/quic-v1/webtransport", port),
		fmt.Sprintf("/ip6/::/udp/%d/webrtc-direct", port+1),
	}

	h, err := libp2p.New(
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.Transport(libp2pwebrtc.New),
		libp2p.Transport(libp2pwebtransport.New),
		libp2p.Identity(pk),
		libp2p.ListenAddrStrings(listenAddrStrings...),
		libp2p.EnableAutoNATv2(),
		libp2p.UDPBlackHoleSuccessCounter(nil),
		libp2p.IPv6BlackHoleSuccessCounter(nil),
	)
	if err != nil {
		panic(err)
	}
	go ProbeAutoNATV2Server(h)
	for _, a := range h.Addrs() {
		fmt.Printf("%s/p2p/%s\n", a, h.ID())
	}
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

type autonatv2er interface {
	AutoNATV2() *autonatv2.AutoNAT
}

func ProbeAutoNATV2Server(h host.Host) {
	ah, ok := h.(autonatv2er)
	if !ok {
		panic(fmt.Sprintf("invalid host %T", h))
	}

	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		autonatServer := s.Text()
		if autonatServer == "" {
			continue
		}
		pi, err := connectToServer(h, autonatServer)
		if err != nil {
			fmt.Println("error")
		}
		defer h.Network().ClosePeer(pi.ID)
		for _, a := range h.Addrs() {
			if !manet.IsPublicAddr(a) {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			res, err := ah.AutoNATV2().GetReachability(ctx, []autonatv2.Request{{Addr: a, SendDialData: true}})
			if err != nil {
				fmt.Println("autonatv2 failed: addr: ", a, err)
			} else {
				fmt.Printf("Addr: %s\nReachability: %s\nStatus: %s\n\n\n", res.Addr, res.Reachability, res.Status)
			}
			cancel()
			time.Sleep(1 * time.Second)
		}
	}
}

func connectToServer(h host.Host, autonatServer string) (peer.AddrInfo, error) {
	pi, err := peer.AddrInfoFromString(autonatServer)
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = h.Connect(ctx, *pi)
	cancel()
	if err != nil {
		return peer.AddrInfo{}, err
	}
	return *pi, nil
}
