package pstoremem

import (
	"container/heap"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func TestPeerAddrsNextExpiry(t *testing.T) {
	paa := newPeerAddrs()
	pa := &paa
	a1 := ma.StringCast("/ip4/1.2.3.4/udp/1/quic-v1")
	a2 := ma.StringCast("/ip4/1.2.3.4/udp/2/quic-v1")

	// t1 is before t2
	t1 := time.Time{}.Add(1 * time.Second)
	t2 := time.Time{}.Add(2 * time.Second)
	heap.Push(pa, &expiringAddr{Addr: a1, Expires: t1, TTL: 10 * time.Second, Peer: "p1"})
	heap.Push(pa, &expiringAddr{Addr: a2, Expires: t2, TTL: 10 * time.Second, Peer: "p2"})

	if pa.NextExpiry() != t1 {
		t.Fatal("expiry should be set to t1, got", pa.NextExpiry())
	}
}

func TestPeerAddrsHeapProperty(t *testing.T) {
	paa := newPeerAddrs()
	pa := &paa
	addrs := []ma.Multiaddr{}
	expiries := []time.Time{}

	const N = 10000
	for i := 0; i < N; i++ {
		addrs = append(addrs, ma.StringCast(fmt.Sprintf("/ip4/1.2.3.4/udp/%d/quic-v1", i)))
		expiries = append(expiries, time.Time{}.Add(time.Duration(10000-i)*time.Second)) // expiries are in reverse order
		pid := peer.ID(fmt.Sprintf("p%d", i))
		heap.Push(pa, &expiringAddr{Addr: addrs[i], Expires: expiries[i], TTL: 10 * time.Second, Peer: pid})
	}

	for i := N - 1; i >= 0; i-- {
		ea, ok := pa.PopIfExpired(expiries[i])
		require.True(t, ok)
		require.Equal(t, ea.Addr, addrs[i])

		ea, ok = pa.PopIfExpired(expiries[i])
		require.False(t, ok)
		require.Nil(t, ea)
	}
}

func TestPeerAddrsHeapPropertyDeletions(t *testing.T) {
	paa := newPeerAddrs()
	pa := &paa
	expiringAddrs := []*expiringAddr{}

	const N = 10000
	for i := 0; i < N; i++ {
		a := ma.StringCast(fmt.Sprintf("/ip4/1.2.3.4/udp/%d/quic-v1", i))
		e := time.Time{}.Add(time.Duration(10000-i) * time.Second) // expiries are in reverse order
		p := peer.ID(fmt.Sprintf("p%d", i))
		expiringAddrs = append(expiringAddrs, &expiringAddr{Addr: a, Expires: e, TTL: 10 * time.Second, Peer: p})
		heap.Push(pa, expiringAddrs[i])
	}

	// delete every 3rd element
	for i := 0; i < N; i += 3 {
		paa.Delete(expiringAddrs[i])
	}

	for i := N - 1; i >= 0; i-- {
		ea, ok := pa.PopIfExpired(expiringAddrs[i].Expires)
		if i%3 == 0 {
			require.False(t, ok)
			require.Nil(t, ea)
		} else {
			require.True(t, ok)
			require.Equal(t, ea.Addr, expiringAddrs[i].Addr)
		}

		ea, ok = pa.PopIfExpired(expiringAddrs[i].Expires)
		require.False(t, ok)
		require.Nil(t, ea)
	}
}

func TestPeerAddrsHeapPropertyUpdates(t *testing.T) {
	paa := newPeerAddrs()
	pa := &paa
	expiringAddrs := []*expiringAddr{}

	const N = 10000
	for i := 0; i < N; i++ {
		a := ma.StringCast(fmt.Sprintf("/ip4/1.2.3.4/udp/%d/quic-v1", i))
		e := time.Time{}.Add(time.Duration(N-i) * time.Second) // expiries are in reverse order
		p := peer.ID(fmt.Sprintf("p%d", i))
		expiringAddrs = append(expiringAddrs, &expiringAddr{Addr: a, Expires: e, TTL: 10 * time.Second, Peer: p})
		heap.Push(pa, expiringAddrs[i])
	}

	// update every 3rd element to expire at the end
	var endElements []ma.Multiaddr
	for i := 0; i < N; i += 3 {
		expiringAddrs[i].Expires = time.Time{}.Add(1000_000 * time.Second)
		pa.Fix(expiringAddrs[i])
		endElements = append(endElements, expiringAddrs[i].Addr)
	}

	for i := N - 1; i >= 0; i-- {
		if i%3 == 0 {
			continue // skip the elements at the end
		}
		ea, ok := pa.PopIfExpired(expiringAddrs[i].Expires)
		require.True(t, ok, "pos: %d", i)
		require.Equal(t, ea.Addr, expiringAddrs[i].Addr)

		ea, ok = pa.PopIfExpired(expiringAddrs[i].Expires)
		require.False(t, ok)
		require.Nil(t, ea)
	}

	for len(endElements) > 0 {
		ea, ok := pa.PopIfExpired(time.Time{}.Add(1000_000 * time.Second))
		require.True(t, ok)
		require.Contains(t, endElements, ea.Addr)
		endElements = slices.DeleteFunc(endElements, func(a ma.Multiaddr) bool { return ea.Addr.Equal(a) })
	}
}
