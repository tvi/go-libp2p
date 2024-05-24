package main

import (
	"fmt"

	"github.com/libp2p/go-libp2p"
)

func main() {
	h, err := libp2p.New()
	if err != nil {
		fmt.Println(h.ID())
	}
}
