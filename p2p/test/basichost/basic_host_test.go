package basichost

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/rand"
)

func TestNoStreamOverTransientConnection(t *testing.T) {
	h1, err := libp2p.New(
		libp2p.NoListenAddrs,
		libp2p.EnableRelay(),
		libp2p.ResourceManager(&network.NullResourceManager{}),
	)
	require.NoError(t, err)

	h2, err := libp2p.New(
		libp2p.NoListenAddrs,
		libp2p.EnableRelay(),
		libp2p.ResourceManager(&network.NullResourceManager{}),
	)
	require.NoError(t, err)

	relay1, err := libp2p.New()
	require.NoError(t, err)

	_, err = relay.New(relay1)
	require.NoError(t, err)

	relay1info := peer.AddrInfo{
		ID:    relay1.ID(),
		Addrs: relay1.Addrs(),
	}
	err = h1.Connect(context.Background(), relay1info)
	require.NoError(t, err)

	err = h2.Connect(context.Background(), relay1info)
	require.NoError(t, err)

	h2.SetStreamHandler("/testprotocol", func(s network.Stream) {
		fmt.Println("testprotocol")

		// End the example
		s.Close()
	})

	_, err = client.Reserve(context.Background(), h2, relay1info)
	require.NoError(t, err)

	relayaddr := ma.StringCast("/p2p/" + relay1info.ID.String() + "/p2p-circuit/p2p/" + h2.ID().String())

	h2Info := peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: []ma.Multiaddr{relayaddr},
	}
	err = h1.Connect(context.Background(), h2Info)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = network.WithNoDial(ctx, "test")
	_, err = h1.NewStream(ctx, h2.ID(), "/testprotocol")

	require.Error(t, err)

	_, err = h1.NewStream(network.WithUseTransient(context.Background(), "test"), h2.ID(), "/testprotocol")
	require.NoError(t, err)
}

func TestNewStreamTransientConnection(t *testing.T) {
	h1, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/quic-v1"),
		libp2p.EnableRelay(),
		libp2p.ResourceManager(&network.NullResourceManager{}),
	)
	require.NoError(t, err)

	h2, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/quic-v1"),
		libp2p.EnableRelay(),
		libp2p.ResourceManager(&network.NullResourceManager{}),
	)
	require.NoError(t, err)

	relay1, err := libp2p.New()
	require.NoError(t, err)

	_, err = relay.New(relay1)
	require.NoError(t, err)

	relay1info := peer.AddrInfo{
		ID:    relay1.ID(),
		Addrs: relay1.Addrs(),
	}
	err = h1.Connect(context.Background(), relay1info)
	require.NoError(t, err)

	err = h2.Connect(context.Background(), relay1info)
	require.NoError(t, err)

	h2.SetStreamHandler("/testprotocol", func(s network.Stream) {
		fmt.Println("testprotocol")

		// End the example
		s.Close()
	})

	_, err = client.Reserve(context.Background(), h2, relay1info)
	require.NoError(t, err)

	relayaddr := ma.StringCast("/p2p/" + relay1info.ID.String() + "/p2p-circuit/p2p/" + h2.ID().String())

	h1.Peerstore().AddAddr(h2.ID(), relayaddr, peerstore.TempAddrTTL)

	// NewStream should block transient connections till we have a direct connection
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	s, err := h1.NewStream(ctx, h2.ID(), "/testprotocol")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, s)

	// NewStream should return a stream if a direct connection is established
	// while waiting
	done := make(chan bool, 2)
	go func() {
		h1.Peerstore().AddAddrs(h2.ID(), h2.Addrs(), peerstore.TempAddrTTL)
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ctx = network.WithNoDial(ctx, "test")
		s, err = h1.NewStream(ctx, h2.ID(), "/testprotocol")
		require.NoError(t, err)
		require.NotNil(t, s)
		defer s.Close()
		require.Equal(t, s.Conn().Stat().Direction, network.DirInbound)
		done <- true
	}()
	go func() {
		// connect h2 to h1 simulating connection reversal
		h2.Peerstore().AddAddrs(h1.ID(), h1.Addrs(), peerstore.TempAddrTTL)
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		ctx = network.WithForceDirectDial(ctx, "test")
		err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID()})
		assert.NoError(t, err)
		done <- true
	}()
	<-done
	<-done
}

func BenchmarkQUICStreams(b *testing.B) {
	h1, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/quic-v1"),
		libp2p.ResourceManager(&network.NullResourceManager{}),
	)
	require.NoError(b, err)

	h2, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/quic-v1"),
		libp2p.ResourceManager(&network.NullResourceManager{}),
	)
	require.NoError(b, err)

	data := make([]byte, 1000)
	for i := 0; i < len(data); i++ {
		data[i] = byte(i % 256)
	}

	info := make([]byte, 1000)
	h2.SetStreamHandler("/test", func(s network.Stream) {
		for {
			_, err := s.Read(info)
			if err != nil {
				break
			}
		}
		s.Close()
	})
	err = h1.Connect(context.Background(), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		benchConn(h1, h2.ID(), "/test", data)
	}
}

func BenchmarkWebRTCStreams(b *testing.B) {
	data := make([]byte, 1000)
	for i := 0; i < len(data); i++ {
		data[i] = byte(i % 256)
	}

	info := make([]byte, 1000)

	dialers := make([]host.Host, 20)
	for i := 0; i < len(dialers); i++ {
		h, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/webrtc-direct"),
			libp2p.ResourceManager(&network.NullResourceManager{}),
			libp2p.Transport(libp2pwebrtc.New),
		)
		require.NoError(b, err)
		dialers[i] = h
		dialers[i].SetStreamHandler("/test", func(s network.Stream) {
			for {
				_, err := s.Read(info)
				if err != nil {
					break
				}
			}
			s.Close()
		})
	}

	h2, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/webrtc-direct"),
		libp2p.ResourceManager(&network.NullResourceManager{}),
		libp2p.Transport(libp2pwebrtc.New),
	)
	require.NoError(b, err)

	h2.SetStreamHandler("/test", func(s network.Stream) {
		for {
			_, err := s.Read(info)
			if err != nil {
				break
			}
		}
		s.Close()
	})
	for i := 0; i < len(dialers); i++ {
		err = dialers[i].Connect(context.Background(), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
		require.NoError(b, err)
		for {
			if h2.Network().Connectedness(dialers[i].ID()) != network.Connected {
				time.Sleep(100 * time.Millisecond)
			}
			break
		}
	}
	for i := 0; i < b.N; i++ {
		j := i % len(dialers)
		if rand.Intn(2) == 0 {
			benchConn(dialers[j], h2.ID(), "/test", data)
		} else {
			benchConn(h2, dialers[j].ID(), "/test", data)
		}
		runtime.GC()
	}
}

func benchConn(h host.Host, p peer.ID, proto string, data []byte) {
	s, err := h.NewStream(context.Background(), p, "/test")
	if err != nil {
		panic(err)
	}
	s.Write(data)
	s.CloseWrite()
	s.Read(data)
	s.Close()
}
