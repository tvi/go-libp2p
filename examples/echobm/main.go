package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	bufSize = 1000_000
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
	select {}
}

func runServer() {
	port := os.Args[2]
	var addr string
	tpt := os.Args[3]
	if tpt == "quic" {
		addr = fmt.Sprintf("/ip4/0.0.0.0/udp/%s/quic-v1", port)
	} else {
		addr = fmt.Sprintf("/ip4/0.0.0.0/udp/%s/webrtc-direct", port)
	}
	h, err := libp2p.New(
		libp2p.Transport(libp2pwebrtc.New),
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.ListenAddrStrings(addr),
		libp2p.ResourceManager(&network.NullResourceManager{}),
	)
	if err != nil {
		panic(err)
	}

	var totalBytes atomic.Int64

	h.SetStreamHandler("echobench10M", func(s network.Stream) {
		buf := make([]byte, bufSize)
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
					return
				}
				tw += n
				totalBytes.Add(int64(n))
				if tw == N {
					break
				}
				if tw > N {
					panic("short write")
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

	go func() {
		http.ListenAndServe("0.0.0.0:5001", promhttp.Handler())
	}()
}

func runClient() {
	srv := os.Args[2]
	conns, err := strconv.Atoi(os.Args[3])
	if err != nil {
		panic(err)
	}
	streams, err := strconv.Atoi(os.Args[4])
	if err != nil {
		panic(err)
	}
	for i := 0; i < conns; i++ {
		runClientConn(srv, streams)
	}
}

func runClientConn(server string, streams int) {
	h, err := libp2p.New(
		libp2p.Transport(libp2pwebrtc.New),
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.NoListenAddrs,
		libp2p.ResourceManager(&network.NullResourceManager{}),
	)
	if err != nil {
		panic(err)
	}

	ai, err := peer.AddrInfoFromString(server)
	if err != nil {
		panic(err)
	}

	h.Peerstore().AddAddrs(ai.ID, ai.Addrs, peerstore.PermanentAddrTTL)
	for i := 0; i < streams; i++ {
		s, err := h.NewStream(context.Background(), ai.ID, "echobench10M")
		if err != nil {
			panic(err)
		}
		go runClientStream(s)
	}
}

func runClientStream(s network.Stream) {
	buf := make([]byte, bufSize)
	for {
		tw := 0
		for {
			n, err := s.Write(buf)
			if err != nil {
				fmt.Println("stream completed with", s.Conn().RemoteMultiaddr(), err)
				return
			}
			tw += n
			if tw == N {
				break
			}
			if tw > N {
				panic("short write")
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
