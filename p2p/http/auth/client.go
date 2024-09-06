package httppeeridauth

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/http/auth/internal/handshake"
)

type ClientPeerIDAuth struct {
	PrivKey  crypto.PrivKey
	TokenTTL time.Duration

	tokenMapMu sync.Mutex
	tokenMap   map[string]tokenInfo
}

type tokenInfo struct {
	token      string
	insertedAt time.Time
	peerID     peer.ID
}

// AuthenticatedDo is like http.Client.Do, but it does the libp2p peer ID auth
// handshake if needed.
//
// It is recommended to pass in an http.Request with `GetBody` set, so that this
// method can retry sending the request in case a previously used token has
// expired.
func (a *ClientPeerIDAuth) AuthenticatedDo(client *http.Client, req *http.Request) (peer.ID, *http.Response, error) {
	hostname := req.Host
	a.tokenMapMu.Lock()
	if a.tokenMap == nil {
		a.tokenMap = make(map[string]tokenInfo)
	}
	ti, hasToken := a.tokenMap[hostname]
	if hasToken && a.TokenTTL != 0 && time.Since(ti.insertedAt) > a.TokenTTL {
		hasToken = false
		delete(a.tokenMap, hostname)
	}
	a.tokenMapMu.Unlock()

	clientIntiatesHandshake := !hasToken
	handshake := handshake.PeerIDAuthHandshakeClient{
		Hostname: hostname,
		PrivKey:  a.PrivKey,
	}
	if clientIntiatesHandshake {
		handshake.SetInitiateChallenge()
	}

	if hasToken {
		// Try to make the request with the token
		req.Header.Set("Authorization", ti.token)
		resp, err := client.Do(req)
		if err != nil {
			return "", nil, err
		}
		if resp.StatusCode != http.StatusUnauthorized {
			// our token is still valid
			return ti.peerID, resp, nil
		}
		if req.GetBody == nil {
			// We can't retry this request even if we wanted to.
			// Return the response and an error
			return "", resp, errors.New("expired token. Couldn't run handshake because req.GetBody is nil")
		}
		resp.Body.Close()

		// Token didn't work, we need to re-authenticate.
		// Run the server-initiated handshake
		req = req.Clone(req.Context())
		req.Body, err = req.GetBody()
		if err != nil {
			return "", nil, err
		}

		handshake.ParseHeader(resp.Header)
	}
	originalBody := req.Body

	handshake.Run()
	handshake.SetHeader(req.Header)

	// Don't send the body before we've authenticated the server
	req.Body = nil
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	resp.Body.Close()

	err = handshake.ParseHeader(resp.Header)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse auth header: %w", err)
	}
	err = handshake.Run()
	if err != nil {
		return "", nil, fmt.Errorf("failed to run handshake: %w", err)
	}

	serverWasAuthenticated := false
	_, err = handshake.PeerID()
	if err == nil {
		serverWasAuthenticated = true
	}

	req = req.Clone(req.Context())
	if serverWasAuthenticated {
		req.Body = originalBody
	} else {
		// Don't send the body before we've authenticated the server
		req.Body = nil
	}
	handshake.SetHeader(req.Header)
	resp, err = client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("failed to do authenticated request: %w", err)
	}

	err = handshake.ParseHeader(resp.Header)
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
	a.tokenMap[hostname] = tokenInfo{
		token:      handshake.BearerToken(),
		insertedAt: time.Now(),
		peerID:     serverPeerID,
	}
	a.tokenMapMu.Unlock()

	if serverWasAuthenticated {
		return serverPeerID, resp, nil
	}

	// Server wasn't authenticated earlier.
	// We need to make one final request with the body now that we authenticated
	// the server.
	req = req.Clone(req.Context())
	req.Body = originalBody
	handshake.SetHeader(req.Header)
	resp, err = client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("failed to do authenticated request: %w", err)
	}
	return serverPeerID, resp, nil
}
