package libp2pwebrtc

import (
	"bytes"
	"context"
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
	"github.com/pion/webrtc/v3"
	"github.com/stretchr/testify/require"
)

func benchmarkWebRTC(b *testing.B, N int) {
	s := webrtc.SettingEngine{
		LoggerFactory: pionLoggerFactory,
	}
	s.SetIncludeLoopbackCandidate(true)
	s.SetReceiveMTU(2000)
	s.DetachDataChannels()
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))

	offerPC, err := api.NewPeerConnection(webrtc.Configuration{})
	require.NoError(b, err)
	offerRWCChan := make(chan detachedChan, 1)
	offerDC, err := offerPC.CreateDataChannel("data", nil)
	require.NoError(b, err)
	offerDC.OnOpen(func() {
		rwc, err := offerDC.Detach()
		require.NoError(b, err)
		offerRWCChan <- detachedChan{rwc: rwc, dc: offerDC}
	})

	answerPC, err := api.NewPeerConnection(webrtc.Configuration{})
	require.NoError(b, err)

	answerChan := make(chan detachedChan, 1)
	answerPC.OnDataChannel(func(dc *webrtc.DataChannel) {
		dc.OnOpen(func() {
			rwc, err := dc.Detach()
			require.NoError(b, err)
			answerChan <- detachedChan{rwc: rwc, dc: dc}
		})
	})

	// Set ICE Candidate handlers. As soon as a PeerConnection has gathered a candidate send it to the other peer
	answerPC.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate != nil {
			require.NoError(b, offerPC.AddICECandidate(candidate.ToJSON()))
		}
	})
	offerPC.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate != nil {
			require.NoError(b, answerPC.AddICECandidate(candidate.ToJSON()))
		}
	})

	// Set the handler for Peer connection state
	// This will notify you when the peer has connected/disconnected
	offerPC.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateFailed {
			b.Log("peer connection failed on offerer")
		}
	})

	// Set the handler for Peer connection state
	// This will notify you when the peer has connected/disconnected
	answerPC.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateFailed {
			b.Log("peer connection failed on answerer")
		}
	})

	// Now, create an offer
	offer, err := offerPC.CreateOffer(nil)
	require.NoError(b, err)
	require.NoError(b, answerPC.SetRemoteDescription(offer))
	require.NoError(b, offerPC.SetLocalDescription(offer))

	answer, err := answerPC.CreateAnswer(nil)
	require.NoError(b, err)
	require.NoError(b, offerPC.SetRemoteDescription(answer))
	require.NoError(b, answerPC.SetLocalDescription(answer))

	<-answerChan
	<-offerRWCChan
	dc1 := make([]detachedChan, 0)
	dc2 := make([]detachedChan, 0)
	pkts := make([][]byte, 100)
	for i := range pkts {
		pkts[i] = make([]byte, 1)
	}
	for i := 0; i < N; i++ {
		d1, err := offerPC.CreateDataChannel("", nil)
		require.NoError(b, err)
		dd1, err := d1.Detach()
		for _, p := range pkts {
			dd1.Write(p)
		}
		require.NoError(b, err)
		d2 := <-answerChan
		dc2 = append(dc2, d2)
		dc1 = append(dc1, detachedChan{rwc: dd1, dc: d1})
		d2.rwc.Close()
	}
	fmt.Println(len(dc2), len(dc1))
	runtime.GC()
}

func bencmkarkWebRTCListener(p peer.ID, listener transport.Listener, dialer *WebRTCTransport, conns, streams, bufSize int) ([]transport.CapableConn, error) {
	errs := make(chan error, conns*streams)
	buf := make([]byte, bufSize)
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
				time.Sleep(300 * time.Millisecond)
			}
		}
	}

	runListenConn := func(conn transport.CapableConn) {
		for {
			s, err := conn.AcceptStream()
			if err != nil {
				errs <- err
				return
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
	for i := 0; i < streams*conns; i++ {
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
		conns, err = bencmkarkWebRTCListener(p, listener, dialer, 10, 1000, 1000_000)
		require.NoError(b, err)
	}
	fmt.Println(len(conns))
	runtime.GC()
}
