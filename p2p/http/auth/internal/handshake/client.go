package handshake

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type peerIDAuthClientState int

const (
	peerIDAuthClientStateSignChallenge peerIDAuthClientState = iota
	peerIDAuthClientStateVerifyChallenge
	peerIDAuthClientStateDone // We have the bearer token, and there's nothing left to do
)

type PeerIDAuthHandshakeClient struct {
	Hostname string
	PrivKey  crypto.PrivKey

	serverPeerID    peer.ID
	ran             bool
	state           peerIDAuthClientState
	p               params
	hb              headerBuilder
	challengeServer [challengeLen]byte
}

var errMissingChallenge = errors.New("missing challenge")

func (h *PeerIDAuthHandshakeClient) ParseHeaderVal(headerVal []byte) error {
	if h.state == peerIDAuthClientStateDone {
		return nil
	}
	h.p = params{}

	if len(headerVal) == 0 {
		return errMissingChallenge
	}

	err := h.p.parsePeerIDAuthSchemeParams(headerVal)
	if err != nil {
		return err
	}

	if h.p.challengeClient != nil {
		h.state = peerIDAuthClientStateSignChallenge
		return nil
	}

	if h.p.sigB64 != nil {
		h.state = peerIDAuthClientStateVerifyChallenge
		return nil
	}

	return errors.New("missing challenge or signature")
}

func (h *PeerIDAuthHandshakeClient) Run() error {
	h.ran = true
	clientPubKeyBytes, err := crypto.MarshalPublicKey(h.PrivKey.GetPublic())
	if err != nil {
		return err
	}
	switch h.state {
	case peerIDAuthClientStateSignChallenge:
		clientSig, err := sign(h.PrivKey, PeerIDAuthScheme, []sigParam{
			{"challenge-client", h.p.challengeClient},
			{"hostname", []byte(h.Hostname)},
		})
		if err != nil {
			return fmt.Errorf("failed to sign challenge: %w", err)
		}
		_, err = rand.Read(h.challengeServer[:])
		if err != nil {
			return err
		}
		copy(h.challengeServer[:], base64.URLEncoding.AppendEncode(nil, h.challengeServer[:]))

		h.hb.clear()
		h.hb.writeScheme(PeerIDAuthScheme)
		h.hb.writeParamB64(nil, "public-key", clientPubKeyBytes)
		h.hb.writeParam("opaque", h.p.opaqueB64)
		h.hb.writeParam("challenge-server", h.challengeServer[:])
		h.hb.writeParamB64(nil, "sig", clientSig)
		return nil
	case peerIDAuthClientStateVerifyChallenge:
		serverPubKeyBytes, err := base64.URLEncoding.AppendDecode(nil, h.p.publicKeyB64)
		if err != nil {
			return err
		}
		sig, err := base64.URLEncoding.AppendDecode(nil, h.p.sigB64)
		if err != nil {
			return fmt.Errorf("failed to decode signature: %w", err)
		}
		serverPubKey, err := crypto.UnmarshalPublicKey(serverPubKeyBytes)
		if err != nil {
			return err
		}
		err = verifySig(serverPubKey, PeerIDAuthScheme, []sigParam{
			{"challenge-server", h.challengeServer[:]},
			{"client-public-key", clientPubKeyBytes},
			{"hostname", []byte(h.Hostname)},
		}, sig)
		if err != nil {
			return err
		}
		h.serverPeerID, err = peer.IDFromPublicKey(serverPubKey)
		if err != nil {
			return err
		}

		h.hb.clear()
		h.hb.writeScheme(PeerIDAuthScheme)
		h.hb.writeParam("bearer", h.p.bearerTokenB64)
		h.state = peerIDAuthClientStateDone

		return nil
	case peerIDAuthClientStateDone:
		return nil
	}

	return errors.New("unhandled state")
}

// PeerID returns the peer ID of the authenticated client.
func (h *PeerIDAuthHandshakeClient) PeerID() (peer.ID, error) {
	if !h.ran {
		return "", errNotRan
	}
	switch h.state {
	case peerIDAuthClientStateVerifyChallenge:
	case peerIDAuthClientStateDone:
	default:
		return "", errors.New("not in proper state")
	}

	return h.serverPeerID, nil
}

func (h *PeerIDAuthHandshakeClient) SetHeader(hdr http.Header) {
	if !h.ran {
		return
	}
	hdr.Set("Authorization", h.hb.b.String())
}

// BearerToken returns the server given bearer token for the client. Set this on
// the Authorization header in the client's request.
func (h *PeerIDAuthHandshakeClient) BearerToken() string {
	if h.state != peerIDAuthClientStateDone {
		return ""
	}
	return h.hb.b.String()
}
