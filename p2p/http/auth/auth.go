package httppeeridauth

import (
	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/p2p/http/auth/internal/handshake"
)

const PeerIDAuthScheme = handshake.PeerIDAuthScheme

var log = logging.Logger("httppeeridauth")
