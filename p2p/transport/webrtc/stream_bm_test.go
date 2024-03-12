package libp2pwebrtc

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func bencmkarkWebRTCListener(p peer.ID, listener transport.Listener, dialer *WebRTCTransport, conns, streams, bufSize int) ([]transport.CapableConn, error) {
	errs := make(chan error, conns*streams)
	buf := make([]byte, bufSize)
	rand.Read(buf)
	pingPong := func(s network.MuxedStream) (err error) {
		defer func() {
			errs <- err
		}()
		defer s.Close()
		_, err = s.Write(buf)
		if err != nil {
			return err
		}
		err = s.CloseWrite()
		if err != nil {
			return err
		}
		res, err := io.ReadAll(s)
		if err != nil {
			return err
		}
		if !bytes.Equal(res, buf) {
			return errors.New("byte mismatch")
		}
		return nil
	}

	echo := func(s network.MuxedStream) {
		buf, _ := io.ReadAll(s)
		s.Write(buf)
		s.Close()
	}

	runDialConn := func(conn transport.CapableConn) {
		for i := 0; i < streams; i++ {
			s, err := conn.OpenStream(context.Background())
			if err != nil {
				errs <- err
				return
			}
			go pingPong(s)
			if i%10 == 0 {
				time.Sleep(500 * time.Millisecond)
			}
		}
	}

	runListenConn := func(conn transport.CapableConn) {
		for {
			s, err := conn.AcceptStream()
			if err != nil {
				errs <- err
				return
			} else {
				errs <- nil
			}
			go echo(s)
		}
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				errs <- err
				return
			} else {
				errs <- nil
			}
			go runListenConn(conn)
		}
	}()

	res := make([]transport.CapableConn, conns)
	for i := 0; i < conns; i++ {
		conn, err := dialer.Dial(context.Background(), listener.Multiaddr(), p)
		if err != nil {
			return nil, err
		}
		res[i] = conn
		go runDialConn(conn)
	}
	for i := 0; i < 2*streams*conns+conns; i++ {
		fmt.Println(i)
		err := <-errs
		if err != nil {
			return res, err
		}
	}
	runtime.GC()
	return res, nil
}

func BenchmarkStreams(b *testing.B) {
	b.ReportAllocs()
	tr, p := getTransport(b)
	listenMultiaddr := ma.StringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")
	listener, err := tr.Listen(listenMultiaddr)
	require.NoError(b, err)

	dialer, _ := getTransport(b)
	var conns []transport.CapableConn
	for i := 0; i < b.N; i++ {
		fmt.Println("bm", i)
		conns, err = bencmkarkWebRTCListener(p, listener, dialer, 1, 1000, 1000_000)
		require.NoError(b, err)
	}
	fmt.Println(len(conns))
	runtime.GC()
}
