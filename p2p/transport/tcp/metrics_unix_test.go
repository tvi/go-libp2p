// go:build: unix

package tcp

import (
	"testing"

	tptu "github.com/libp2p/go-libp2p/p2p/net/upgrader"
	"github.com/libp2p/go-libp2p/p2p/transport/tcpreuse"
	ttransport "github.com/libp2p/go-libp2p/p2p/transport/testsuite"

	"github.com/stretchr/testify/require"
)

func TestTcpTransportCollectsMetricsWithSharedTcpSocket(t *testing.T) {
	peerA, ia := makeInsecureMuxer(t)
	_, ib := makeInsecureMuxer(t)

	sharedTCPSocketA := tcpreuse.NewConnMgr(false, nil, nil)
	sharedTCPSocketB := tcpreuse.NewConnMgr(false, nil, nil)

	ua, err := tptu.New(ia, muxers, nil, nil, nil)
	require.NoError(t, err)
	ta, err := NewTCPTransport(ua, nil, sharedTCPSocketA, WithMetrics())
	require.NoError(t, err)
	ub, err := tptu.New(ib, muxers, nil, nil, nil)
	require.NoError(t, err)
	tb, err := NewTCPTransport(ub, nil, sharedTCPSocketB, WithMetrics())
	require.NoError(t, err)

	zero := "/ip4/127.0.0.1/tcp/0"
	ttransport.SubtestTransport(t, ta, tb, zero, peerA)
}
