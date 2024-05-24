package main

import (
	"fmt"

	"github.com/libp2p/go-libp2p"
)

func main() {
	h, err := libp2p.New(
		libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/4001",
			"/ip6/::/tcp/4001",
		),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(h.Addrs())
	select {}
}
