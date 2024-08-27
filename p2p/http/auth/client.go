package httppeeridauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type ClientPeerIDAuth struct {
	PrivKey crypto.PrivKey
}

// AddAuthTokenToRequest adds the libp2p-Bearer token to the request. Returns the peer ID of the server.
func (a *ClientPeerIDAuth) AddAuthTokenToRequest(req *http.Request) (peer.ID, error) {
	panic("todo")
}

// MutualAuth performs mutual authentication with the server at the given endpoint. Returns the server's peer id.
func (a *ClientPeerIDAuth) MutualAuth(ctx context.Context, client *http.Client, authEndpoint string, hostname string) (peer.ID, error) {
	panic("todo")
}

// authSelfToServer performs the initial authentication request to the server. It authenticates the client to the server.
// Returns the Authorization value with libp2p-PeerID scheme to use for subsequent requests.
func (a *ClientPeerIDAuth) authSelfToServer(ctx context.Context, client *http.Client, myPeerID peer.ID, challengeServer []byte, authEndpoint string, hostname string) (string, error) {
	r, err := http.NewRequestWithContext(ctx, "POST", authEndpoint, nil)
	r.Host = hostname
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// do the initial auth request
	resp, err := client.Do(r)
	if err != nil {
		return "", fmt.Errorf("failed to do initial auth request: %w", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return "", nil
	}
	resp.Body.Close()

	authHeader := resp.Header.Get("WWW-Authenticate")
	f, err := parseAuthFields(authHeader, hostname, false)
	if err != nil {
		return "", fmt.Errorf("failed to parse our auth header: %w", err)
	}

	if len(f.challengeClientB64) == 0 {
		return "", errors.New("missing challenge")
	}
	panic("todo")
}
