package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
)

func main() {
	conns, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}
	streams, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}
	addr := os.Args[3]
	pi, err := peer.AddrInfoFromString(addr)
	if err != nil {
		panic(err)
	}
	for i := 0; i < conns; i += 10 {
		var wg sync.WaitGroup
		wg.Add(10)
		for k := 0; k < 10; k++ {
			go func() {
				defer wg.Done()
				h, err := libp2p.New(
					libp2p.ResourceManager(&network.NullResourceManager{}),
					libp2p.Transport(libp2pwebrtc.New),
					libp2p.Transport(libp2pquic.NewTransport),
					libp2p.NoListenAddrs,
				)
				if err != nil {
					panic(err)
				}
				h.Peerstore().AddAddrs(pi.ID, pi.Addrs, peerstore.PermanentAddrTTL)
				for i := 0; i < streams; i++ {
					s, err := h.NewStream(context.Background(), pi.ID, "echo100k")
					if err != nil {
						panic(err)
					}
					go run(s)
				}
			}()
		}
		wg.Wait()
	}
	select {}
}

func run(s network.Stream) {
	s.SetDeadline(time.Time{})
	totalSize := 100_000
	buf := make([]byte, totalSize)
	for {
		nw, err := s.Write(buf)
		if err != nil {
			fmt.Println("write err", nw, err)
			return
		}
		nr := 0
		for {
			n, err := s.Read(buf)
			if err != nil {
				fmt.Println("read err", nr, err)
				return
			}
			nr += n
			if nr >= totalSize {
				break
			}
		}
		time.Sleep(1 * time.Second)
	}
}
