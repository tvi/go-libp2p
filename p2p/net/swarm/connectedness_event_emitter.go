package swarm

import (
	"context"
	"sync"

	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// connectednessEventEmitter emits PeerConnectednessChanged events.
// We ensure that for any peer we connected to we always sent atleast 1 NotConnected Event after
// the peer disconnects. This is because peers can observe a connection before they are notified
// of the connection by a peer connectedness changed event.
type connectednessEventEmitter struct {
	mx sync.RWMutex
	// newConns is the channel that holds the peerIDs we recently connected to
	newConns      chan peer.ID
	removeConnsMx sync.Mutex
	// removeConns is a slice of peerIDs we have recently closed connections to
	removeConns []peer.ID
	// lastEvent is the last connectedness event sent for a particular peer.
	lastEvent map[peer.ID]network.Connectedness
	// connectedness is the function that gives the peers current connectedness state
	connectedness func(peer.ID) network.Connectedness
	// emitter is the PeerConnectednessChanged event emitter
	emitter         event.Emitter
	wg              sync.WaitGroup
	removeConnNotif chan struct{}
	ctx             context.Context
	cancel          context.CancelFunc
}

func newConnectednessEventEmitter(connectedness func(peer.ID) network.Connectedness, emitter event.Emitter) *connectednessEventEmitter {
	ctx, cancel := context.WithCancel(context.Background())
	c := &connectednessEventEmitter{
		newConns:        make(chan peer.ID, 32),
		lastEvent:       make(map[peer.ID]network.Connectedness),
		removeConnNotif: make(chan struct{}, 1),
		connectedness:   connectedness,
		emitter:         emitter,
		ctx:             ctx,
		cancel:          cancel,
	}
	c.wg.Add(1)
	go c.runEmitter()
	return c
}

func (c *connectednessEventEmitter) AddConn(p peer.ID) {
	c.mx.RLock()
	defer c.mx.RUnlock()
	if c.ctx.Err() != nil {
		return
	}

	c.newConns <- p
}

func (c *connectednessEventEmitter) RemoveConn(p peer.ID) {
	c.mx.RLock()
	defer c.mx.RUnlock()
	if c.ctx.Err() != nil {
		return
	}

	c.removeConnsMx.Lock()
	// This queue is not unbounded since we block in the AddConn method
	// So we are adding connections to the swarm only at a rate
	// the subscriber for our peer connectedness changed events can consume them.
	// If a lot of open connections are closed at once, increasing the disconnected
	// event notification rate, the rate of adding connections to the swarm would
	// proportionately reduce, which would eventually reduce the length of this slice.
	c.removeConns = append(c.removeConns, p)
	c.removeConnsMx.Unlock()

	select {
	case c.removeConnNotif <- struct{}{}:
	default:
	}
}

func (c *connectednessEventEmitter) Close() {
	c.cancel()
	c.wg.Wait()
}

func (c *connectednessEventEmitter) runEmitter() {
	defer c.wg.Done()
	for {
		select {
		case p := <-c.newConns:
			c.notifyPeer(p, true)
		case <-c.removeConnNotif:
			c.sendConnRemovedNotifications()
		case <-c.ctx.Done():
			c.mx.Lock() // Wait for all pending AddConn & RemoveConn operations to complete
			defer c.mx.Unlock()
			for {
				select {
				case p := <-c.newConns:
					c.notifyPeer(p, true)
				case <-c.removeConnNotif:
					c.sendConnRemovedNotifications()
				default:
					return
				}
			}
		}
	}
}

func (c *connectednessEventEmitter) notifyPeer(p peer.ID, forceNotConnectedEvent bool) {
	oldState := c.lastEvent[p]
	c.lastEvent[p] = c.connectedness(p)
	if c.lastEvent[p] == network.NotConnected {
		delete(c.lastEvent, p)
	}
	if (forceNotConnectedEvent && c.lastEvent[p] == network.NotConnected) || c.lastEvent[p] != oldState {
		c.emitter.Emit(event.EvtPeerConnectednessChanged{
			Peer:          p,
			Connectedness: c.lastEvent[p],
		})
	}
}

func (c *connectednessEventEmitter) sendConnRemovedNotifications() {
	c.removeConnsMx.Lock()
	defer c.removeConnsMx.Unlock()
	for {
		if len(c.removeConns) == 0 {
			return
		}
		p := c.removeConns[0]
		c.removeConns[0] = ""
		c.removeConns = c.removeConns[1:]

		c.removeConnsMx.Unlock()
		c.notifyPeer(p, false)
		c.removeConnsMx.Lock()
	}
}
