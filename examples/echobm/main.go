package main

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
)

const (
	bufSize = 100_000
	N       = 10_000_000
)

func main() {
	mode := os.Args[1]
	if mode == "server" {
		runServer()
	} else if mode == "client" {
		runClient()
	} else {
		panic("invalid mode")
	}
}

func runServer() {
	port := os.Args[2]
	addr := fmt.Sprintf("/ip4/0.0.0.0/udp/%s/webrtc-direct", port)
	h, err := libp2p.New(
		libp2p.Transport(libp2pwebrtc.New),
		libp2p.ListenAddrStrings(addr),
	)
	if err != nil {
		panic(err)
	}

	var totalBytes atomic.Int64

	h.SetStreamHandler("echobench10M", func(s network.Stream) {
		buf := make([]byte, 100_000)
		for {
			tr := 0
			for {
				n, err := s.Read(buf)
				if err != nil {
					fmt.Println("stream completed with", s.Conn().RemoteMultiaddr(), err)
					return
				}
				tr += n
				totalBytes.Add(int64(n))
				if tr >= N {
					break
				}
			}
			tw := 0
			for {
				n, err := s.Write(buf)
				if err != nil {
					fmt.Println("stream completed with", s.Conn().RemoteMultiaddr(), err)
				}
				tw += n
				totalBytes.Add(int64(n))
				if tw >= N {
					break
				}
			}
		}
	})
	fmt.Println("server started")
	for _, a := range h.Addrs() {
		fmt.Printf("%s/p2p/%s\n\n", a, h.ID())
	}
	go func() {
		prevBytes := 0
		for {
			time.Sleep(1 * time.Second)
			tb := totalBytes.Load()
			bytesTransferred := tb - int64(prevBytes)
			prevBytes = int(tb)
			if bytesTransferred == 0 {
				continue
			}
			speed := float64(bytesTransferred*8) / (1000_000)
			fmt.Printf("throughput: %0.1f Mb/s\n", speed)
		}
	}()
	select {}
}

func runClient() {
	srv := os.Args[2]
	h, err := libp2p.New(
		libp2p.Transport(libp2pwebrtc.New),
		libp2p.NoListenAddrs,
	)
	if err != nil {
		panic(err)
	}

	ai, err := peer.AddrInfoFromString(srv)
	if err != nil {
		panic(err)
	}

	h.Peerstore().AddAddrs(ai.ID, ai.Addrs, peerstore.PermanentAddrTTL)
	s, err := h.NewStream(context.Background(), ai.ID, "echobench10M")
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 100_000)
	for {
		tw := 0
		for {
			n, err := s.Write(buf)
			if err != nil {
				fmt.Println("stream completed with", s.Conn().RemoteMultiaddr(), err)
				return
			}
			tw += n
			if tw >= N {
				break
			}
		}
		tr := 0
		for {
			n, err := s.Read(buf)
			if err != nil {
				fmt.Println("stream completed with", s.Conn().RemoteMultiaddr(), err)
				return
			}
			tr += n
			if tr >= N {
				break
			}
		}
	}
}
