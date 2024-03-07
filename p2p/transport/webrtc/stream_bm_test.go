package libp2pwebrtc

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/pion/webrtc/v3"
	"github.com/stretchr/testify/require"
)

func benchmarkWebRTCMemory(b *testing.B, N int) {
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

func BenchmarkStreams(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkWebRTCMemory(b, 10000)
	}
}
