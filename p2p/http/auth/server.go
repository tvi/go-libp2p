package httppeeridauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
)

const maxAuthHeaderSize = 8192

const challengeTTL = 5 * time.Minute

type ServerPeerIDAuth struct {
	PrivKey        crypto.PrivKey
	ValidHostnames map[string]struct{}
	TokenTTL       time.Duration
	Next           http.Handler
	// InsecureNoTLS is a flag that allows the server to accept requests without a TLS ServerName. Used only for testing.
	InsecureNoTLS bool
}

var errMissingAuthHeader = errors.New("missing header")

// ServeHTTP implements the http.Handler interface for PeerIDAuth. It will
// attempt to authenticate the request using using the libp2p peer ID auth
// scheme. If a Next handler is set, it will be called on authenticated
// requests.
func (a *ServerPeerIDAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hostname := r.Host
	if !a.InsecureNoTLS {
		if r.TLS == nil {
			log.Debugf("No TLS connection, and InsecureNoTLS is false")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if hostname != r.TLS.ServerName {
			log.Debugf("Unauthorized request for host %s: hostname mismatch. Expected %s", hostname, r.TLS.ServerName)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
}
