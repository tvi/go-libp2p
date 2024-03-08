package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {

	h, err := libp2p.New(
		libp2p.ResourceManager(&network.NullResourceManager{}),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/udp/4003/webrtc-direct", "/ip4/0.0.0.0/udp/4004/quic-v1"),
		libp2p.Transport(libp2pwebrtc.New),
		libp2p.Transport(libp2pquic.NewTransport),
	)
	if err != nil {
		panic(err)
	}
	var mx sync.Mutex
	var total, nextMark int
	start := time.Now()
	h.SetStreamHandler("echo100k", func(s network.Stream) {
		defer func() {
			fmt.Println("stream closed!")
		}()
		totalSize := 100_000
		buf := make([]byte, totalSize)
		for {
			nr := 0
			for {
				n, err := s.Read(buf)
				if err != nil {
					fmt.Println("read err", nr, err)
					return
				}
				nr += n
				mx.Lock()
				total += n
				if total >= nextMark {
					fmt.Println("total: ", total, speed(10_000_000, time.Since(start)), "KB/s", len(h.Network().Peers()))
					nextMark += 10_000_000
					start = time.Now()
				}
				mx.Unlock()
				if nr >= totalSize {
					nw, err := s.Write(buf)
					if err != nil {
						fmt.Println("write err", nw, err)
						return
					}
					break
				}
			}
		}
	})
	go func() {
		if err := http.ListenAndServe("0.0.0.0:5001", promhttp.Handler()); err != nil {
			panic(err)
		}
	}()

	id := h.ID()
	for _, a := range h.Addrs() {
		fmt.Printf("%s/p2p/%s\n", a, id)
	}
	select {}
}

func speed(n int, d time.Duration) int {
	return int(n / int(d.Seconds()*1000))
}
