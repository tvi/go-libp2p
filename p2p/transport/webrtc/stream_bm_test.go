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
	errs := make(chan error, 10*conns*streams)
	buf := make([]byte, bufSize)
	rand.Read(buf)

	pingPong := func(s network.MuxedStream) (err error) {
		defer func() {
			errs <- err
		}()
		defer s.Close()
		res := make([]byte, bufSize)
		for i := 0; i < 100; i++ {
			_, err = s.Write(buf)
			if err != nil {
				return err
			}
			rt, n := 0, 0
			rb := res
			for rt < bufSize {
				n, err = s.Read(rb)
				if err != nil && err != io.EOF {
					errs <- err
					return err
				}
				rt += n
				if err == io.EOF {
					break
				}
				rb = res[rt:]
			}
			if !bytes.Equal(res, buf) {
				return errors.New("byte mismatch")
			}
		}
		return nil
	}

	echo := func(s network.MuxedStream) {
		buf := make([]byte, bufSize)
		for i := 0; i < 100; i++ {
			rt := 0
			b := buf
			for rt < bufSize {
				n, err := s.Read(b)
				if err != nil && err != io.EOF {
					errs <- err
					return
				}
				rt += n
				if err == io.EOF {
					break
				}
				b = buf[rt:]
			}
			if rt != bufSize {
				errs <- errors.New("short read")
			}
			s.Write(buf)
		}
		s.Close()
	}

	runDialConn := func(conn transport.CapableConn) {
		buf := make([]byte, 10)
		for i := 0; i < streams; i++ {
			s, err := conn.OpenStream(context.Background())
			if err != nil {
				errs <- err
				return
			}
			s.Write(buf)
			_, err = s.Read(buf)
			if err != nil {
				errs <- err
				return
			}
			go pingPong(s)
		}
	}

	runListenConn := func(conn transport.CapableConn) {
		buf := make([]byte, 10)
		for {
			s, err := conn.AcceptStream()
			if err != nil {
				errs <- err
				return
			} else {
				errs <- nil
			}
			_, err = s.Read(buf)
			if err != nil {
				errs <- err
				return
			}
			s.Write(buf)
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

	st := time.Now()
	fmt.Println("STARTED")
	for i := 0; i < 2*streams*conns+conns; i++ {
		err := <-errs
		if err != nil {
			return res, err
		}
	}
	d := time.Since(st)
	fmt.Println("throughput", conns, streams, speed(2*conns*streams*100*bufSize, int(d.Nanoseconds())))
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
		conns, err = bencmkarkWebRTCListener(p, listener, dialer, 2, 10, 2000_000)
		require.NoError(b, err)
	}
	fmt.Println(len(conns))
	runtime.GC()
}

func speed(n int, ns int) string {
	s := float64(n*8) / (float64(ns))
	s *= 1000 // b / ns => Mb / s
	return fmt.Sprintf("%0.1f Mb/s", s)
}
