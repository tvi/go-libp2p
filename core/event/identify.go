package event

import (
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/record"
	"github.com/multiformats/go-multiaddr"
)

// EvtPeerIdentificationCompleted is emitted when the initial identification round for a peer is completed.
type EvtPeerIdentificationCompleted struct {
	// Peer is the ID of the peer whose identification succeeded.
	Peer peer.ID

	// Conn is the connection we identified.
	Conn network.Conn

	// ListenAddrs is the list of addresses the peer is listening on.
	ListenAddrs []multiaddr.Multiaddr

	// Protocols is the list of protocols the peer advertised on this connection.
	Protocols []protocol.ID

	// SignedPeerRecord is the provided signed peer record of the peer. May be nil.
	SignedPeerRecord *record.Envelope
}

// EvtPeerIdentificationFailed is emitted when the initial identification round for a peer failed.
type EvtPeerIdentificationFailed struct {
	// Peer is the ID of the peer whose identification failed.
	Peer peer.ID
	// Reason is the reason why identification failed.
	Reason error
}
