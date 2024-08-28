package httppeeridauth

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/http/auth/internal/handshake"
)

type ClientPeerIDAuth struct {
	PrivKey crypto.PrivKey

	tokenMapMu sync.Mutex
	tokenMap   map[string]tokenInfo
}

type tokenInfo struct {
	token  string
	peerID peer.ID
}

// AddAuthTokenToRequest adds the libp2p-Bearer token to the request. Returns the peer ID of the server.
func (a *ClientPeerIDAuth) AddAuthTokenToRequest(req *http.Request) (peer.ID, error) {
	panic("todo")
}

// AuthenticatedDo is like http.Client.Do, but it does the libp2p peer ID auth handshake if needed.
func (a *ClientPeerIDAuth) AuthenticatedDo(client *http.Client, req *http.Request) (peer.ID, *http.Response, error) {
	clonedReq := req.Clone(req.Context())

	hostname := req.Host
	a.tokenMapMu.Lock()
	if a.tokenMap == nil {
		a.tokenMap = make(map[string]tokenInfo)
	}
	ti, ok := a.tokenMap[hostname]
	a.tokenMapMu.Unlock()
	if ok {
		req.Header.Set("Authorization", ti.token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		// our token is still valid or no auth needed
		return ti.peerID, resp, nil
	}
	resp.Body.Close()

	handshake := handshake.PeerIDAuthHandshakeClient{
		Hostname: hostname,
		PrivKey:  a.PrivKey,
	}
	err = handshake.ParseHeaderVal([]byte(resp.Header.Get("WWW-Authenticate")))
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse auth header: %w", err)
	}
	err = handshake.Run()
	if err != nil {
		return "", nil, fmt.Errorf("failed to run handshake: %w", err)
	}
	handshake.SetHeader(clonedReq.Header)

	resp, err = client.Do(clonedReq)
	if err != nil {
		return "", nil, fmt.Errorf("failed to do authenticated request: %w", err)
	}

	err = handshake.ParseHeaderVal([]byte(resp.Header.Get("Authentication-Info")))
	if err != nil {
		resp.Body.Close()
		return "", nil, fmt.Errorf("failed to parse auth info header: %w", err)
	}
	err = handshake.Run()
	if err != nil {
		resp.Body.Close()
		return "", nil, fmt.Errorf("failed to run auth info handshake: %w", err)
	}

	serverPeerID, err := handshake.PeerID()
	if err != nil {
		resp.Body.Close()
		return "", nil, fmt.Errorf("failed to get server's peer ID: %w", err)
	}
	a.tokenMapMu.Lock()
	a.tokenMap[hostname] = tokenInfo{handshake.BearerToken(), serverPeerID}
	a.tokenMapMu.Unlock()

	return serverPeerID, resp, nil

}
