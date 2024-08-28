package handshake

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

const challengeTTL = 5 * time.Minute

type peerIDAuthServerState int

const (
	peerIDAuthServerStateChallengeClient peerIDAuthServerState = iota
	peerIDAuthServerStateVerifyChallenge
	peerIDAuthServerStateVerifyBearer
)

type opaqueState struct {
	IsToken         bool      `json:"is-token,omitempty"`
	PeerID          peer.ID   `json:"peer-id,omitempty"`
	ChallengeClient string    `json:"challenge-client,omitempty"`
	Hostname        string    `json:"hostname"`
	CreatedTime     time.Time `json:"created-time"`
}

// Marshal serializes the state by appending it to the byte slice.
func (o *opaqueState) Marshal(hmac hash.Hash, b []byte) ([]byte, error) {
	hmac.Reset()
	fieldsMarshalled, err := json.Marshal(o)
	if err != nil {
		return b, err
	}
	_, err = hmac.Write(fieldsMarshalled)
	if err != nil {
		return b, err
	}
	b = hmac.Sum(b)
	b = append(b, fieldsMarshalled...)
	return b, nil
}

var errInvalidHMAC = errors.New("invalid HMAC")

func (o *opaqueState) Unmarshal(hmacImpl hash.Hash, d []byte) error {
	hmacImpl.Reset()
	if len(d) < hmacImpl.Size() {
		return errInvalidHMAC
	}
	hmacVal := d[:hmacImpl.Size()]
	fields := d[hmacImpl.Size():]
	_, err := hmacImpl.Write(fields)
	if err != nil {
		return err
	}
	expectedHmac := hmacImpl.Sum(nil)
	if !hmac.Equal(hmacVal, expectedHmac) {
		return errInvalidHMAC
	}

	err = json.Unmarshal(fields, &o)
	if err != nil {
		return err
	}
	return nil
}

type PeerIDAuthHandshakeServer struct {
	Hostname string
	PrivKey  crypto.PrivKey
	TokenTTL time.Duration
	// used to authenticate opaque blobs and tokens
	Hmac hash.Hash

	ran bool
	buf [1024]byte

	state peerIDAuthServerState
	p     params
	hb    headerBuilder

	opaque opaqueState
}

var errInvalidHeader = errors.New("invalid header")

func (h *PeerIDAuthHandshakeServer) Reset() {
	h.Hmac.Reset()
	h.ran = false
	clear(h.buf[:])
	h.state = 0
	h.p = params{}
	h.hb.clear()
	h.opaque = opaqueState{}
}
func (h *PeerIDAuthHandshakeServer) ParseHeaderVal(headerVal []byte) error {
	if len(headerVal) == 0 {
		// We are in the initial state. Nothing to parse.
		return nil
	}
	err := h.p.parsePeerIDAuthSchemeParams(headerVal)
	if err != nil {
		return err
	}
	if h.p.sigB64 != nil && h.p.opaqueB64 != nil {
		h.state = peerIDAuthServerStateVerifyChallenge
		return nil
	}
	if h.p.bearerTokenB64 != nil {
		h.state = peerIDAuthServerStateVerifyBearer
		return nil
	}

	return errInvalidHeader
}

var errExpiredChallenge = errors.New("challenge expired")
var errExpiredToken = errors.New("token expired")

func (h *PeerIDAuthHandshakeServer) Run() error {
	h.ran = true
	switch h.state {
	case peerIDAuthServerStateChallengeClient:
		h.hb.writeScheme(PeerIDAuthScheme)
		{
			_, err := io.ReadFull(randReader, h.buf[:challengeLen])
			if err != nil {
				return err
			}
			encodedChallenge := base64.URLEncoding.AppendEncode(h.buf[challengeLen:challengeLen], h.buf[:challengeLen])
			h.opaque = opaqueState{
				ChallengeClient: string(encodedChallenge),
				Hostname:        h.Hostname,
				CreatedTime:     nowFn(),
			}
			h.hb.writeParam("challenge-client", encodedChallenge)
		}
		{
			opaqueVal, err := h.opaque.Marshal(h.Hmac, h.buf[:0])
			if err != nil {
				return err
			}
			h.hb.writeParamB64(h.buf[len(opaqueVal):], "opaque", opaqueVal)
		}
	case peerIDAuthServerStateVerifyChallenge:
		{
			opaque, err := base64.URLEncoding.AppendDecode(h.buf[:0], h.p.opaqueB64)
			if err != nil {
				return err
			}
			err = h.opaque.Unmarshal(h.Hmac, opaque)
			if err != nil {
				return err
			}
		}
		if nowFn().After(h.opaque.CreatedTime.Add(challengeTTL)) {
			return errExpiredChallenge
		}
		if h.opaque.IsToken {
			return errors.New("expected challenge, got token")
		}

		if h.Hostname != h.opaque.Hostname {
			return errors.New("hostname in opaque mismatch")
		}

		// If we got a public key, check that it matches the peer id
		if len(h.p.publicKeyB64) == 0 {
			return errors.New("missing public key")
		}
		publicKeyBytes, err := base64.URLEncoding.AppendDecode(nil, h.p.publicKeyB64)
		if err != nil {
			return err
		}
		pubKey, err := crypto.UnmarshalPublicKey(publicKeyBytes)
		if err != nil {
			return err
		}

		{
			sig, err := base64.URLEncoding.AppendDecode(h.buf[:0], h.p.sigB64)
			if err != nil {
				return fmt.Errorf("failed to decode signature: %w", err)
			}
			err = verifySig(pubKey, PeerIDAuthScheme, []sigParam{
				{k: "challenge-client", v: []byte(h.opaque.ChallengeClient)},
				{k: "hostname", v: []byte(h.Hostname)},
			}, sig)
			if err != nil {
				return err
			}
		}

		if len(h.p.challengeServer) < challengeLen {
			return errors.New("challenge too short")
		}
		// We authenticated the client, now authenticate ourselves
		serverSig, err := sign(h.PrivKey, PeerIDAuthScheme, []sigParam{
			{"challenge-server", h.p.challengeServer},
			{"client-public-key", publicKeyBytes},
			{"hostname", []byte(h.Hostname)},
		})
		if err != nil {
			return fmt.Errorf("failed to sign challenge: %w", err)
		}

		peerID, err := peer.IDFromPublicKey(pubKey)
		if err != nil {
			return err
		}

		// And create a bearer token for the client
		h.opaque = opaqueState{
			IsToken:     true,
			PeerID:      peerID,
			Hostname:    h.Hostname,
			CreatedTime: nowFn(),
		}
		serverPubKey := h.PrivKey.GetPublic()
		pubKeyBytes, err := crypto.MarshalPublicKey(serverPubKey)
		if err != nil {
			return err
		}

		h.hb.writeScheme(PeerIDAuthScheme)
		h.hb.writeParamB64(h.buf[:], "sig", serverSig)
		{
			bearerToken, err := h.opaque.Marshal(h.Hmac, h.buf[:0])
			if err != nil {
				return err
			}
			h.hb.writeParamB64(h.buf[len(bearerToken):], "bearer", bearerToken)
		}
		h.hb.writeParamB64(h.buf[:], "public-key", pubKeyBytes)
	case peerIDAuthServerStateVerifyBearer:
		{
			bearerToken, err := base64.URLEncoding.AppendDecode(h.buf[:0], h.p.bearerTokenB64)
			if err != nil {
				return err
			}
			err = h.opaque.Unmarshal(h.Hmac, bearerToken)
			if err != nil {
				return err
			}
		}
		if !h.opaque.IsToken {
			return errors.New("expected token, got challenge")
		}

		if nowFn().After(h.opaque.CreatedTime.Add(h.TokenTTL)) {
			return errExpiredToken
		}

		return nil
	}

	return nil
}

// PeerID returns the peer ID of the authenticated client.
func (h *PeerIDAuthHandshakeServer) PeerID() (peer.ID, error) {
	if !h.ran {
		return "", errNotRan
	}
	switch h.state {
	case peerIDAuthServerStateVerifyChallenge:
	case peerIDAuthServerStateVerifyBearer:
	default:
		return "", errors.New("not in proper state")
	}
	return h.opaque.PeerID, nil
}

func (h *PeerIDAuthHandshakeServer) SetHeader(hdr http.Header) {
	if !h.ran {
		return
	}
	defer h.hb.clear()
	switch h.state {
	case peerIDAuthServerStateChallengeClient:
		hdr.Set("WWW-Authenticate", h.hb.b.String())
	case peerIDAuthServerStateVerifyChallenge:
		hdr.Set("Authentication-Info", h.hb.b.String())
	case peerIDAuthServerStateVerifyBearer:
		// For completeness. Nothing to do
	}
}
