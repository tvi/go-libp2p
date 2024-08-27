package handshake

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

func TestHandshake(t *testing.T) {
	hostname := "example.com"
	serverPriv, _, _ := crypto.GenerateEd25519Key(rand.Reader)
	clientPriv, _, _ := crypto.GenerateEd25519Key(rand.Reader)

	serverHandshake := PeerIDAuthHandshakeServer{
		Hostname: hostname,
		PrivKey:  serverPriv,
		TokenTTL: time.Hour,
		Hmac:     hmac.New(sha256.New, make([]byte, 32)),
	}

	clientHandshake := PeerIDAuthHandshakeClient{
		Hostname: hostname,
		PrivKey:  clientPriv,
	}

	headers := make(http.Header)

	// Start the handshake
	require.NoError(t, serverHandshake.ParseHeaderVal(nil))
	require.NoError(t, serverHandshake.Run())
	serverHandshake.SetHeader(headers)

	// Client receives the challenge and signs it. Also sends the challenge server
	require.NoError(t, clientHandshake.ParseHeaderVal([]byte(headers.Get("WWW-Authenticate"))))
	clear(headers)
	require.NoError(t, clientHandshake.Run())
	clientHandshake.SetHeader(headers)

	// Server receives the sig and verifies it. Also signs the challenge server
	serverHandshake.Reset()
	require.NoError(t, serverHandshake.ParseHeaderVal([]byte(headers.Get("Authorization"))))
	clear(headers)
	require.NoError(t, serverHandshake.Run())
	serverHandshake.SetHeader(headers)

	// Client verifies sig and sets the bearer token for future requests
	require.NoError(t, clientHandshake.ParseHeaderVal([]byte(headers.Get("Authentication-Info"))))
	clear(headers)
	require.NoError(t, clientHandshake.Run())
	clientHandshake.SetHeader(headers)

	// Server verifies the bearer token
	serverHandshake.Reset()
	require.NoError(t, serverHandshake.ParseHeaderVal([]byte(headers.Get("Authorization"))))
	clear(headers)
	require.NoError(t, serverHandshake.Run())
	serverHandshake.SetHeader(headers)

	expectedClientPeerID, _ := peer.IDFromPrivateKey(clientPriv)
	expectedServerPeerID, _ := peer.IDFromPrivateKey(serverPriv)
	clientPeerID, err := serverHandshake.PeerID()
	require.NoError(t, err)
	require.Equal(t, expectedClientPeerID, clientPeerID)

	serverPeerID, err := clientHandshake.PeerID()
	require.NoError(t, err)
	require.Equal(t, expectedServerPeerID, serverPeerID)
}

func BenchmarkServerHandshake(b *testing.B) {
	clientHeader1 := make(http.Header)
	clientHeader2 := make(http.Header)
	headers := make(http.Header)

	hostname := "example.com"
	serverPriv, _, _ := crypto.GenerateEd25519Key(rand.Reader)
	clientPriv, _, _ := crypto.GenerateEd25519Key(rand.Reader)

	serverHandshake := PeerIDAuthHandshakeServer{
		Hostname: hostname,
		PrivKey:  serverPriv,
		TokenTTL: time.Hour,
		Hmac:     hmac.New(sha256.New, make([]byte, 32)),
	}

	clientHandshake := PeerIDAuthHandshakeClient{
		Hostname: hostname,
		PrivKey:  clientPriv,
	}
	require.NoError(b, serverHandshake.ParseHeaderVal(nil))
	require.NoError(b, serverHandshake.Run())
	serverHandshake.SetHeader(headers)

	// Client receives the challenge and signs it. Also sends the challenge server
	require.NoError(b, clientHandshake.ParseHeaderVal([]byte(headers.Get("WWW-Authenticate"))))
	clear(headers)
	require.NoError(b, clientHandshake.Run())
	clientHandshake.SetHeader(clientHeader1)

	// Server receives the sig and verifies it. Also signs the challenge server
	serverHandshake.Reset()
	require.NoError(b, serverHandshake.ParseHeaderVal([]byte(clientHeader1.Get("Authorization"))))
	clear(headers)
	require.NoError(b, serverHandshake.Run())
	serverHandshake.SetHeader(headers)

	// Client verifies sig and sets the bearer token for future requests
	require.NoError(b, clientHandshake.ParseHeaderVal([]byte(headers.Get("Authentication-Info"))))
	clear(headers)
	require.NoError(b, clientHandshake.Run())
	clientHandshake.SetHeader(clientHeader2)

	// Server verifies the bearer token
	serverHandshake.Reset()
	require.NoError(b, serverHandshake.ParseHeaderVal([]byte(clientHeader2.Get("Authorization"))))
	clear(headers)
	require.NoError(b, serverHandshake.Run())
	serverHandshake.SetHeader(headers)

	initialClientAuth := []byte(clientHeader1.Get("Authorization"))
	bearerClientAuth := []byte(clientHeader2.Get("Authorization"))
	_ = initialClientAuth
	_ = bearerClientAuth

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		serverHandshake.Reset()
		serverHandshake.ParseHeaderVal(nil)
		serverHandshake.Run()

		serverHandshake.Reset()
		serverHandshake.ParseHeaderVal(initialClientAuth)
		serverHandshake.Run()

		serverHandshake.Reset()
		serverHandshake.ParseHeaderVal(bearerClientAuth)
		serverHandshake.Run()
	}

}

func TestParsePeerIDAuthSchemeParams(t *testing.T) {
	str := `libp2p-PeerID sig="<base64-signature-bytes>", public-key="<base64-encoded-public-key-bytes>", bearer="<base64-encoded-opaque-blob>"`
	p := params{}
	expectedParam := params{
		sigB64:         []byte(`<base64-signature-bytes>`),
		publicKeyB64:   []byte(`<base64-encoded-public-key-bytes>`),
		bearerTokenB64: []byte(`<base64-encoded-opaque-blob>`),
	}
	err := p.parsePeerIDAuthSchemeParams([]byte(str))
	require.NoError(t, err)
	require.Equal(t, expectedParam, p)
}

func BenchmarkParsePeerIDAuthSchemeParams(b *testing.B) {
	str := []byte(`libp2p-PeerID peer-id="<server-peer-id-string>", sig="<base64-signature-bytes>", public-key="<base64-encoded-public-key-bytes>", bearer="<base64-encoded-opaque-blob>"`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := params{}
		err := p.parsePeerIDAuthSchemeParams(str)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestHeaderBuilder(t *testing.T) {
	hb := headerBuilder{}
	hb.writeScheme(PeerIDAuthScheme)
	hb.writeParam("peer-id", []byte("foo"))
	hb.writeParam("challenge-client", []byte("something-else"))
	hb.writeParam("hostname", []byte("example.com"))

	expected := `libp2p-PeerID peer-id="foo", challenge-client="something-else", hostname="example.com"`
	require.Equal(t, expected, hb.b.String())
}

func BenchmarkHeaderBuilder(b *testing.B) {
	h := headerBuilder{}
	scratch := make([]byte, 256)
	scratch = scratch[:0]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.b.Grow(256)
		h.writeParamB64(scratch, "foo", []byte("bar"))
		h.clear()
	}
}

// Test Vectors
var zeroBytes = make([]byte, 64)
var zeroKey, _, _ = crypto.GenerateEd25519Key(bytes.NewReader(zeroBytes))

// Peer ID derived from the zero key
var zeroID, _ = peer.IDFromPublicKey(zeroKey.GetPublic())

func TestOpaqueStateRoundTrip(t *testing.T) {
	zeroBytes := [32]byte{}

	// To drop the monotonic clock reading
	timeAfterUnmarshal := time.Now()
	b, err := json.Marshal(timeAfterUnmarshal)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &timeAfterUnmarshal))
	hmac := hmac.New(sha256.New, zeroBytes[:])

	o := opaqueState{
		ChallengeClient: "foo-bar",
		CreatedTime:     timeAfterUnmarshal,
		IsToken:         true,
		PeerID:          &zeroID,
		Hostname:        "example.com",
	}

	hmac.Reset()
	b, err = o.Marshal(hmac, nil)
	require.NoError(t, err)

	o2 := opaqueState{}

	hmac.Reset()
	err = o2.Unmarshal(hmac, b)
	require.NoError(t, err)
	require.EqualValues(t, o, o2)
}

func FuzzServerHandshakeNoPanic(f *testing.F) {
	zeroBytes := [32]byte{}
	hmac := hmac.New(sha256.New, zeroBytes[:])

	f.Fuzz(func(t *testing.T, data []byte) {
		hmac.Reset()
		h := PeerIDAuthHandshakeServer{
			Hostname: "example.com",
			PrivKey:  zeroKey,
			Hmac:     hmac,
		}
		err := h.ParseHeaderVal(data)
		if err != nil {
			return
		}
		err = h.Run()
		if err != nil {
			return
		}
		h.PeerID()
	})
}

func BenchmarkOpaqueStateWrite(b *testing.B) {
	zeroBytes := [32]byte{}
	hmac := hmac.New(sha256.New, zeroBytes[:])
	o := opaqueState{
		ChallengeClient: "foo-bar",
		CreatedTime:     time.Now(),
	}
	d := make([]byte, 512)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hmac.Reset()
		_, err := o.Marshal(hmac, d[:0])
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpaqueStateRead(b *testing.B) {
	zeroBytes := [32]byte{}
	hmac := hmac.New(sha256.New, zeroBytes[:])
	o := opaqueState{
		ChallengeClient: "foo-bar",
		CreatedTime:     time.Now(),
	}
	d := make([]byte, 256)
	d, err := o.Marshal(hmac, d[:0])
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hmac.Reset()
		err := o.Unmarshal(hmac, d)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzParsePeerIDAuthSchemeParamsNoPanic(f *testing.F) {
	p := params{}
	// Just check that we don't panic
	f.Fuzz(func(t *testing.T, data []byte) {
		p.parsePeerIDAuthSchemeParams(data)
	})
}
