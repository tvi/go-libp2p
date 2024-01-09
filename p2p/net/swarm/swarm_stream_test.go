package swarm

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
)

type asyncStreamWrapper struct {
	network.MuxedStream
	beforeClose func()
	done        chan bool
}

func (s *asyncStreamWrapper) AsyncClose(onDone func()) error {
	s.beforeClose()
	err := s.Close()
	go func() {
		<-s.done
		onDone()
	}()
	return err
}

func TestStreamAsyncCloser(t *testing.T) {
	s1 := makeSwarm(t)
	s2 := makeSwarm(t)

	s1.Peerstore().AddAddrs(s2.LocalPeer(), s2.ListenAddresses(), peerstore.TempAddrTTL)

	var mx sync.Mutex
	var wg1, wg2 sync.WaitGroup
	var closed int
	done := make(chan bool)
	const N = 100
	wg1.Add(N)
	// wg2 blocks all goroutines in the beforeClose method. This allows us to check GetStreams
	// works concurrently with Close
	wg2.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			s, err := s1.NewStream(context.Background(), s2.LocalPeer())
			require.NoError(t, err)
			ss, ok := s.(*Stream)
			require.True(t, ok)
			as := &asyncStreamWrapper{
				MuxedStream: ss.stream,
				beforeClose: func() {
					wg2.Done()
					mx.Lock()
					defer mx.Unlock()
					closed++
					wg1.Done()
				},
				done: done,
			}
			ss.stream = as
			ss.Close()
		}()
	}
	wg2.Wait()
	require.Eventually(t, func() bool { return s1.Connectedness(s2.LocalPeer()) == network.Connected },
		5*time.Second, 100*time.Millisecond)
	require.Equal(t, len(s1.ConnsToPeer(s2.LocalPeer())[0].GetStreams()), N)

	wg1.Wait()
	require.Equal(t, closed, N)
	// Streams should only be removed from the connection after the onDone call back is executed
	require.Equal(t, len(s1.ConnsToPeer(s2.LocalPeer())[0].GetStreams()), N)

	for i := 0; i < N; i++ {
		done <- true
	}
	require.Eventually(t, func() bool {
		return len(s1.ConnsToPeer(s2.LocalPeer())[0].GetStreams()) == 0
	}, 5*time.Second, 100*time.Millisecond)
}
