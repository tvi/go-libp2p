package httppeeridauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"net/http"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/http/auth/internal/handshake"
)

type ServerPeerIDAuth struct {
	PrivKey  crypto.PrivKey
	TokenTTL time.Duration
	Next     func(peer peer.ID, w http.ResponseWriter, r *http.Request)
	// InsecureNoTLS is a flag that allows the server to accept requests without a TLS ServerName. Used only for testing.
	InsecureNoTLS bool
	// Only used when InsecureNoTLS is true. If set, the server will only accept requests for the hostnames which return true
	ValidHostnameFn func(string) bool

	Hmac     hash.Hash
	initHmac sync.Once
}

// ServeHTTP implements the http.Handler interface for PeerIDAuth. It will
// attempt to authenticate the request using using the libp2p peer ID auth
// scheme. If a Next handler is set, it will be called on authenticated
// requests.
func (a *ServerPeerIDAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.initHmac.Do(func() {
		if a.Hmac == nil {
			key := make([]byte, 32)
			_, err := rand.Read(key)
			if err != nil {
				panic(err)
			}
			a.Hmac = hmac.New(sha256.New, key)
		}
	})

	hostname := r.Host
	if a.InsecureNoTLS {
		if a.ValidHostnameFn == nil {
			log.Debugf("No ValidHostnameFn set for InsecureNoTLS")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !a.ValidHostnameFn(hostname) {
			log.Debugf("Unauthorized request for host %s: hostname not in valid set", hostname)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
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

	handshake := handshake.PeerIDAuthHandshakeServer{
		Hostname: hostname,
		PrivKey:  a.PrivKey,
		TokenTTL: a.TokenTTL,
		Hmac:     a.Hmac,
	}
	err := handshake.ParseHeaderVal([]byte(r.Header.Get("Authorization")))
	if err != nil {
		log.Debugf("Failed to parse header: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = handshake.Run()
	if err != nil {
		log.Debugf("Failed to run handshake: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	handshake.SetHeader(w.Header())

	peer, err := handshake.PeerID()
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if a.Next == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	a.Next(peer, w, r)
}
