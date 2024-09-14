package pstoremem

import (
	"container/heap"
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	pstore "github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/record"
	"github.com/libp2p/go-libp2p/p2p/internal/instanttimer"

	logging "github.com/ipfs/go-log/v2"
	ma "github.com/multiformats/go-multiaddr"
)

var SignedPeerRecordBound = 1_000

var log = logging.Logger("peerstore")

type expiringAddr struct {
	Addr    ma.Multiaddr
	TTL     time.Duration
	Expires time.Time
	Peer    peer.ID
	// to sort by expiry time
	heapIndex int
}

func (e *expiringAddr) ExpiredBy(t time.Time) bool {
	return !t.Before(e.Expires)
}

type peerRecordState struct {
	Envelope *record.Envelope
	Seq      uint64
}

// Essentially Go stdlib's Priority Queue example
var _ heap.Interface = &peerAddrs{}

type peerAddrs struct {
	addrs        map[peer.ID]map[string]*expiringAddr // peer.ID -> addr.Bytes() -> *expiringAddr
	expiringHeap []*expiringAddr
}

func newPeerAddrs() *peerAddrs {
	return &peerAddrs{
		addrs: make(map[peer.ID]map[string]*expiringAddr),
	}
}

func (pa *peerAddrs) Len() int { return len(pa.expiringHeap) }
func (pa *peerAddrs) Less(i, j int) bool {
	return pa.expiringHeap[i].Expires.Before(pa.expiringHeap[j].Expires)
}
func (pa *peerAddrs) Swap(i, j int) {
	pa.expiringHeap[i], pa.expiringHeap[j] = pa.expiringHeap[j], pa.expiringHeap[i]
	pa.expiringHeap[i].heapIndex = i
	pa.expiringHeap[j].heapIndex = j
}
func (pa *peerAddrs) Push(x any) {
	a := x.(*expiringAddr)
	if _, ok := pa.addrs[a.Peer]; !ok {
		pa.addrs[a.Peer] = make(map[string]*expiringAddr)
	}
	pa.addrs[a.Peer][string(a.Addr.Bytes())] = a
	a.heapIndex = len(pa.expiringHeap)
	pa.expiringHeap = append(pa.expiringHeap, a)
}
func (pa *peerAddrs) Pop() any {
	old := pa.expiringHeap
	n := len(old)
	a := old[n-1]
	a.heapIndex = -1
	pa.expiringHeap = old[0 : n-1]

	if m, ok := pa.addrs[a.Peer]; ok {
		delete(m, string(a.Addr.Bytes()))
		if len(m) == 0 {
			delete(pa.addrs, a.Peer)
		}
	}

	return a
}

func (pa *peerAddrs) Fix(a *expiringAddr) {
	heap.Fix(pa, a.heapIndex)
}

func (pa *peerAddrs) Delete(a *expiringAddr) {
	heap.Remove(pa, a.heapIndex)
	a.heapIndex = -1
	if m, ok := pa.addrs[a.Peer]; ok {
		delete(m, string(a.Addr.Bytes()))
		if len(m) == 0 {
			delete(pa.addrs, a.Peer)
		}
	}
}

func (pa *peerAddrs) FindAddr(p peer.ID, addrBytes ma.Multiaddr) (*expiringAddr, bool) {
	if m, ok := pa.addrs[p]; ok {
		v, ok := m[string(addrBytes.Bytes())]
		return v, ok
	}
	return nil, false
}

func (pa *peerAddrs) NextExpiry() time.Time {
	if len(pa.expiringHeap) == 0 {
		return time.Time{}
	}
	return pa.expiringHeap[len(pa.expiringHeap)-1].Expires
}

func (pa *peerAddrs) gc(now time.Time) {
	for len(pa.expiringHeap) > 0 && now.After(pa.NextExpiry()) {
		heap.Pop(pa)
	}
}

// memoryAddrBook manages addresses.
type memoryAddrBook struct {
	mu sync.RWMutex
	// TODO bound the number of not connected addresses we store.
	addrs             *peerAddrs
	signedPeerRecords map[peer.ID]*peerRecordState

	refCount    sync.WaitGroup
	cancel      func()
	updateTimer chan struct{}

	subManager *AddrSubManager
	clock      instanttimer.Clock
}

var _ pstore.AddrBook = (*memoryAddrBook)(nil)
var _ pstore.CertifiedAddrBook = (*memoryAddrBook)(nil)

func NewAddrBook() *memoryAddrBook {
	ctx, cancel := context.WithCancel(context.Background())

	ab := &memoryAddrBook{
		addrs:             newPeerAddrs(),
		signedPeerRecords: make(map[peer.ID]*peerRecordState),
		subManager:        NewAddrSubManager(),
		cancel:            cancel,
		updateTimer:       make(chan struct{}, 1),
		clock:             instanttimer.RealClock{},
	}
	ab.refCount.Add(1)
	go ab.background(ctx)
	return ab
}

type AddrBookOption func(book *memoryAddrBook) error

func WithClock(clock instanttimer.Clock) AddrBookOption {
	return func(book *memoryAddrBook) error {
		book.clock = clock
		return nil
	}
}

// background periodically schedules a gc. Let's us clean up expired addresses
// in batches.
func (mab *memoryAddrBook) background(ctx context.Context) {
	defer mab.refCount.Done()
	const atMostFreq = 1 * time.Minute
	timer := mab.clock.InstantTimer(mab.clock.Now().Add(atMostFreq))
	defer timer.Stop()
	nextRun := mab.clock.Now().Add(atMostFreq)

	for {
		select {
		case <-mab.updateTimer:
			now := mab.clock.Now()
			mab.mu.RLock()
			nextExpiry := mab.addrs.NextExpiry()
			mab.mu.RUnlock()

			if nextExpiry.Before(nextRun) {
				// The next expiry is sooner than the next scheduled run
				// but we only want to run at most `atMostFreq`.
				// So only reset the timer if we are more than `atMostFreq` away
				if nextRun.Sub(now) > atMostFreq {
					dur := max(atMostFreq, nextExpiry.Sub(now))
					if !timer.Stop() {
						<-timer.Ch()
					}
					nextRun = now.Add(dur)
					timer.Reset(nextRun)
				}
			}
		case <-timer.Ch():
			mab.gc()

			now := mab.clock.Now()
			mab.mu.RLock()
			nextExpiry := mab.addrs.NextExpiry()
			mab.mu.RUnlock()
			timeToNextExpiry := nextExpiry.Sub(now)
			dur := max(atMostFreq, timeToNextExpiry)
			nextRun = now.Add(dur)
			timer.Reset(nextRun)
		case <-ctx.Done():
			return
		}
	}
}

func (mab *memoryAddrBook) maybeUpdateTimerUnlocked(oldNextExpiry time.Time) {
	nextExpiry := mab.addrs.NextExpiry()
	if oldNextExpiry.IsZero() || nextExpiry.Before(oldNextExpiry) {
		select {
		case mab.updateTimer <- struct{}{}:
		default:
		}
	}
}

func (mab *memoryAddrBook) Close() error {
	mab.cancel()
	mab.refCount.Wait()
	return nil
}

// gc garbage collects the in-memory address book.
func (mab *memoryAddrBook) gc() {
	now := mab.clock.Now()
	mab.mu.Lock()
	defer mab.mu.Unlock()
	mab.addrs.gc(now)
}

func (mab *memoryAddrBook) PeersWithAddrs() peer.IDSlice {
	mab.mu.RLock()
	defer mab.mu.RUnlock()
	peers := make(peer.IDSlice, 0, len(mab.addrs.addrs))
	for pid := range mab.addrs.addrs {
		peers = append(peers, pid)
	}
	return peers
}

// AddAddr calls AddAddrs(p, []ma.Multiaddr{addr}, ttl)
func (mab *memoryAddrBook) AddAddr(p peer.ID, addr ma.Multiaddr, ttl time.Duration) {
	mab.AddAddrs(p, []ma.Multiaddr{addr}, ttl)
}

// AddAddrs gives memoryAddrBook addresses to use, with a given ttl
// (time-to-live), after which the address is no longer valid.
// This function never reduces the TTL or expiration of an address.
func (mab *memoryAddrBook) AddAddrs(p peer.ID, addrs []ma.Multiaddr, ttl time.Duration) {
	// if we have a valid peer record, ignore unsigned addrs
	// peerRec := mab.GetPeerRecord(p)
	// if peerRec != nil {
	// 	return
	// }
	mab.addAddrs(p, addrs, ttl)
}

var ErrTooManyRecords = fmt.Errorf("too many signed peer records. Dropping this one")

// ConsumePeerRecord adds addresses from a signed peer.PeerRecord (contained in
// a record.Envelope), which will expire after the given TTL.
// See https://godoc.org/github.com/libp2p/go-libp2p/core/peerstore#CertifiedAddrBook for more details.
func (mab *memoryAddrBook) ConsumePeerRecord(recordEnvelope *record.Envelope, ttl time.Duration) (bool, error) {
	r, err := recordEnvelope.Record()
	if err != nil {
		return false, err
	}
	rec, ok := r.(*peer.PeerRecord)
	if !ok {
		return false, fmt.Errorf("unable to process envelope: not a PeerRecord")
	}
	if !rec.PeerID.MatchesPublicKey(recordEnvelope.PublicKey) {
		return false, fmt.Errorf("signing key does not match PeerID in PeerRecord")
	}

	// ensure seq is greater than, or equal to, the last received
	mab.mu.Lock()
	defer mab.mu.Unlock()
	if (len(mab.signedPeerRecords)) >= SignedPeerRecordBound {
		return false, ErrTooManyRecords
	}

	lastState, found := mab.signedPeerRecords[rec.PeerID]
	if found && lastState.Seq > rec.Seq {
		return false, nil
	}
	mab.signedPeerRecords[rec.PeerID] = &peerRecordState{
		Envelope: recordEnvelope,
		Seq:      rec.Seq,
	}
	mab.addAddrsUnlocked(rec.PeerID, rec.Addrs, ttl)
	return true, nil
}

func (mab *memoryAddrBook) addAddrs(p peer.ID, addrs []ma.Multiaddr, ttl time.Duration) {
	mab.mu.Lock()
	defer mab.mu.Unlock()

	mab.addAddrsUnlocked(p, addrs, ttl)
}

func (mab *memoryAddrBook) addAddrsUnlocked(p peer.ID, addrs []ma.Multiaddr, ttl time.Duration) {
	defer mab.maybeUpdateTimerUnlocked(mab.addrs.NextExpiry())
	// if ttl is zero, exit. nothing to do.
	if ttl <= 0 {
		return
	}

	exp := mab.clock.Now().Add(ttl)
	for _, addr := range addrs {
		// Remove suffix of /p2p/peer-id from address
		addr, addrPid := peer.SplitAddr(addr)
		if addr == nil {
			log.Warnw("Was passed nil multiaddr", "peer", p)
			continue
		}
		if addrPid != "" && addrPid != p {
			log.Warnf("Was passed p2p address with a different peerId. found: %s, expected: %s", addrPid, p)
			continue
		}
		// find the highest TTL and Expiry time between
		// existing records and function args
		a, found := mab.addrs.FindAddr(p, addr)
		if !found {
			// not found, announce it.
			entry := &expiringAddr{Addr: addr, Expires: exp, TTL: ttl, Peer: p}
			heap.Push(mab.addrs, entry)
			mab.subManager.BroadcastAddr(p, addr)
		} else {
			// update ttl & exp to whichever is greater between new and existing entry
			var changed bool
			if ttl > a.TTL {
				changed = true
				a.TTL = ttl
			}
			if exp.After(a.Expires) {
				changed = true
				a.Expires = exp
			}
			if changed {
				mab.addrs.Fix(a)
			}
		}
	}
}

// SetAddr calls mgr.SetAddrs(p, addr, ttl)
func (mab *memoryAddrBook) SetAddr(p peer.ID, addr ma.Multiaddr, ttl time.Duration) {
	mab.SetAddrs(p, []ma.Multiaddr{addr}, ttl)
}

// SetAddrs sets the ttl on addresses. This clears any TTL there previously.
// This is used when we receive the best estimate of the validity of an address.
func (mab *memoryAddrBook) SetAddrs(p peer.ID, addrs []ma.Multiaddr, ttl time.Duration) {
	defer mab.maybeUpdateTimerUnlocked(mab.addrs.NextExpiry())
	mab.mu.Lock()
	defer mab.mu.Unlock()

	exp := mab.clock.Now().Add(ttl)
	for _, addr := range addrs {
		addr, addrPid := peer.SplitAddr(addr)
		if addr == nil {
			log.Warnw("was passed nil multiaddr", "peer", p)
			continue
		}
		if addrPid != "" && addrPid != p {
			log.Warnf("was passed p2p address with a different peerId, found: %s wanted: %s", addrPid, p)
			continue
		}

		if a, found := mab.addrs.FindAddr(p, addr); found {
			// re-set all of them for new ttl.
			if ttl > 0 {
				a.Addr = addr
				a.Expires = exp
				a.TTL = ttl
				mab.addrs.Fix(a)
				mab.subManager.BroadcastAddr(p, addr)
			} else {
				mab.addrs.Delete(a)
			}
		} else {
			if ttl > 0 {
				heap.Push(mab.addrs, &expiringAddr{Addr: addr, Expires: exp, TTL: ttl, Peer: p})
				mab.subManager.BroadcastAddr(p, addr)
			}
		}
	}
}

// UpdateAddrs updates the addresses associated with the given peer that have
// the given oldTTL to have the given newTTL.
func (mab *memoryAddrBook) UpdateAddrs(p peer.ID, oldTTL time.Duration, newTTL time.Duration) {
	mab.mu.Lock()
	defer mab.mu.Unlock()
	exp := mab.clock.Now().Add(newTTL)

	for _, a := range mab.addrs.addrs[p] {
		if oldTTL == a.TTL {
			if newTTL == 0 {
				mab.addrs.Delete(a)
			} else {
				a.TTL = newTTL
				a.Expires = exp
				mab.addrs.Fix(a)
			}
		}
	}
}

// Addrs returns all known (and valid) addresses for a given peer
func (mab *memoryAddrBook) Addrs(p peer.ID) []ma.Multiaddr {
	mab.mu.RLock()
	defer mab.mu.RUnlock()

	if _, ok := mab.addrs.addrs[p]; !ok {
		return nil
	}
	return validAddrs(mab.clock.Now(), mab.addrs.addrs[p])
}

func validAddrs(now time.Time, amap map[string]*expiringAddr) []ma.Multiaddr {
	good := make([]ma.Multiaddr, 0, len(amap))
	if amap == nil {
		return good
	}
	for _, m := range amap {
		if !m.ExpiredBy(now) {
			good = append(good, m.Addr)
		}
	}

	return good
}

// GetPeerRecord returns a Envelope containing a PeerRecord for the
// given peer id, if one exists.
// Returns nil if no signed PeerRecord exists for the peer.
func (mab *memoryAddrBook) GetPeerRecord(p peer.ID) *record.Envelope {
	mab.mu.RLock()
	defer mab.mu.RUnlock()

	if _, ok := mab.addrs.addrs[p]; !ok {
		return nil
	}
	// although the signed record gets garbage collected when all addrs inside it are expired,
	// we may be in between the expiration time and the GC interval
	// so, we check to see if we have any valid signed addrs before returning the record
	if len(validAddrs(mab.clock.Now(), mab.addrs.addrs[p])) == 0 {
		return nil
	}

	state := mab.signedPeerRecords[p]
	if state == nil {
		return nil
	}
	return state.Envelope
}

// ClearAddrs removes all previously stored addresses
func (mab *memoryAddrBook) ClearAddrs(p peer.ID) {
	defer mab.maybeUpdateTimerUnlocked(mab.addrs.NextExpiry())
	mab.mu.Lock()
	defer mab.mu.Unlock()

	delete(mab.signedPeerRecords, p)
	for _, a := range mab.addrs.addrs[p] {
		mab.addrs.Delete(a)
	}
}

// AddrStream returns a channel on which all new addresses discovered for a
// given peer ID will be published.
func (mab *memoryAddrBook) AddrStream(ctx context.Context, p peer.ID) <-chan ma.Multiaddr {
	var initial []ma.Multiaddr

	mab.mu.RLock()
	if m, ok := mab.addrs.addrs[p]; ok {
		initial = make([]ma.Multiaddr, 0, len(m))
		for _, a := range m {
			initial = append(initial, a.Addr)
		}
	}
	mab.mu.RUnlock()

	return mab.subManager.AddrStream(ctx, p, initial)
}

type addrSub struct {
	pubch chan ma.Multiaddr
	ctx   context.Context
}

func (s *addrSub) pubAddr(a ma.Multiaddr) {
	select {
	case s.pubch <- a:
	case <-s.ctx.Done():
	}
}

// An abstracted, pub-sub manager for address streams. Extracted from
// memoryAddrBook in order to support additional implementations.
type AddrSubManager struct {
	mu   sync.RWMutex
	subs map[peer.ID][]*addrSub
}

// NewAddrSubManager initializes an AddrSubManager.
func NewAddrSubManager() *AddrSubManager {
	return &AddrSubManager{
		subs: make(map[peer.ID][]*addrSub),
	}
}

// Used internally by the address stream coroutine to remove a subscription
// from the manager.
func (mgr *AddrSubManager) removeSub(p peer.ID, s *addrSub) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	subs := mgr.subs[p]
	if len(subs) == 1 {
		if subs[0] != s {
			return
		}
		delete(mgr.subs, p)
		return
	}

	for i, v := range subs {
		if v == s {
			subs[i] = subs[len(subs)-1]
			subs[len(subs)-1] = nil
			mgr.subs[p] = subs[:len(subs)-1]
			return
		}
	}
}

// BroadcastAddr broadcasts a new address to all subscribed streams.
func (mgr *AddrSubManager) BroadcastAddr(p peer.ID, addr ma.Multiaddr) {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	if subs, ok := mgr.subs[p]; ok {
		for _, sub := range subs {
			sub.pubAddr(addr)
		}
	}
}

// AddrStream creates a new subscription for a given peer ID, pre-populating the
// channel with any addresses we might already have on file.
func (mgr *AddrSubManager) AddrStream(ctx context.Context, p peer.ID, initial []ma.Multiaddr) <-chan ma.Multiaddr {
	sub := &addrSub{pubch: make(chan ma.Multiaddr), ctx: ctx}
	out := make(chan ma.Multiaddr)

	mgr.mu.Lock()
	mgr.subs[p] = append(mgr.subs[p], sub)
	mgr.mu.Unlock()

	sort.Sort(addrList(initial))

	go func(buffer []ma.Multiaddr) {
		defer close(out)

		sent := make(map[string]struct{}, len(buffer))
		for _, a := range buffer {
			sent[string(a.Bytes())] = struct{}{}
		}

		var outch chan ma.Multiaddr
		var next ma.Multiaddr
		if len(buffer) > 0 {
			next = buffer[0]
			buffer = buffer[1:]
			outch = out
		}

		for {
			select {
			case outch <- next:
				if len(buffer) > 0 {
					next = buffer[0]
					buffer = buffer[1:]
				} else {
					outch = nil
					next = nil
				}
			case naddr := <-sub.pubch:
				if _, ok := sent[string(naddr.Bytes())]; ok {
					continue
				}
				sent[string(naddr.Bytes())] = struct{}{}

				if next == nil {
					next = naddr
					outch = out
				} else {
					buffer = append(buffer, naddr)
				}
			case <-ctx.Done():
				mgr.removeSub(p, sub)
				return
			}
		}
	}(initial)

	return out
}
