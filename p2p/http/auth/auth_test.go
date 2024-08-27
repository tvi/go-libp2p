package httppeeridauth

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"

	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

// TestMutualAuth tests that we can do a mutually authenticated round trip
func TestMutualAuth(t *testing.T) {
	logging.SetLogLevel("httppeeridauth", "DEBUG")

	zeroBytes := make([]byte, 64)
	serverKey, _, err := crypto.GenerateEd25519Key(bytes.NewReader(zeroBytes))
	require.NoError(t, err)

	type clientTestCase struct {
		name         string
		clientKeyGen func(t *testing.T) crypto.PrivKey
	}

	clientTestCases := []clientTestCase{
		{
			name: "ED25519",
			clientKeyGen: func(t *testing.T) crypto.PrivKey {
				t.Helper()
				clientKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
				require.NoError(t, err)
				return clientKey
			},
		},
		{
			name: "RSA",
			clientKeyGen: func(t *testing.T) crypto.PrivKey {
				t.Helper()
				clientKey, _, err := crypto.GenerateRSAKeyPair(2048, rand.Reader)
				require.NoError(t, err)
				return clientKey
			},
		},
	}

	type serverTestCase struct {
		name      string
		serverGen func(t *testing.T) (*httptest.Server, *ServerPeerIDAuth)
	}

	serverTestCases := []serverTestCase{
		{
			name: "no TLS",
			serverGen: func(t *testing.T) (*httptest.Server, *ServerPeerIDAuth) {
				t.Helper()
				auth := ServerPeerIDAuth{
					PrivKey:        serverKey,
					ValidHostnames: map[string]struct{}{"example.com": {}},
					TokenTTL:       time.Hour,
					InsecureNoTLS:  true,
				}

				ts := httptest.NewServer(&auth)
				t.Cleanup(ts.Close)
				return ts, &auth
			},
		},
		{
			name: "TLS",
			serverGen: func(t *testing.T) (*httptest.Server, *ServerPeerIDAuth) {
				t.Helper()
				auth := ServerPeerIDAuth{
					PrivKey:        serverKey,
					ValidHostnames: map[string]struct{}{"example.com": {}},
					TokenTTL:       time.Hour,
				}

				ts := httptest.NewTLSServer(&auth)
				t.Cleanup(ts.Close)
				return ts, &auth
			},
		},
	}

	for _, ctc := range clientTestCases {
		for _, stc := range serverTestCases {
			t.Run(ctc.name+"+"+stc.name, func(t *testing.T) {
				// ts, serverAuth := stc.serverGen(t)
				// client := ts.Client()
				// tlsClientConfig := client.Transport.(*http.Transport).TLSClientConfig
				// if tlsClientConfig != nil {
				// 	// If we're using TLS, we need to set the SNI so that the
				// 	// server can verify the request Host matches it.
				// 	tlsClientConfig.ServerName = "example.com"
				// }
				// clientKey := ctc.clientKeyGen(t)
				// clientAuth := ClientPeerIDAuth{PrivKey: clientKey}

				// expectedServerID, err := peer.IDFromPrivateKey(serverKey)
				// require.NoError(t, err)

				// ctx := context.Background()
				// serverID, err := clientAuth.MutualAuth(ctx, client, ts.URL, "example.com")
				// require.NoError(t, err)
				// require.Equal(t, expectedServerID, serverID)
				// require.NotZero(t, clientAuth.tokenMap["example.com"])

				// // Once more with the auth token
				// req, err := http.NewRequest("GET", ts.URL, nil)
				// require.NoError(t, err)
				// req.Host = "example.com"
				// serverID, err = clientAuth.AddAuthTokenToRequest(req)
				// require.NoError(t, err)
				// require.Equal(t, expectedServerID, serverID)

				// // Verify that unwrapping our token gives us the client's peer ID
				// expectedClientPeerID, err := peer.IDFromPrivateKey(clientKey)
				// require.NoError(t, err)
				// clientPeerID, err := serverAuth.UnwrapBearerToken(req, req.Host)
				// require.NoError(t, err)
				// require.Equal(t, expectedClientPeerID, clientPeerID)

				// // Verify that we can make an authenticated request
				// resp, err := client.Do(req)
				// require.NoError(t, err)

				// require.Equal(t, http.StatusOK, resp.StatusCode)
			})
		}
	}
}

func FuzzServeHTTP(f *testing.F) {
	zeroBytes := make([]byte, 64)
	serverKey, _, err := crypto.GenerateEd25519Key(bytes.NewReader(zeroBytes))
	require.NoError(f, err)
	auth := ServerPeerIDAuth{
		PrivKey:        serverKey,
		ValidHostnames: map[string]struct{}{"example.com": {}},
		TokenTTL:       time.Hour,
		InsecureNoTLS:  true,
	}
	// Just check that we don't panic'
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		hostLen := int(data[0])
		data = data[1:]
		if hostLen > len(data) {
			return
		}
		host := string(data[:hostLen])
		data = data[hostLen:]
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Host = host
		req.Header.Set("Authorization", string(data))
		auth.ServeHTTP(httptest.NewRecorder(), req)
	})
}

// Test Vectors
var zeroBytes = make([]byte, 64)
var zeroKey, _, _ = crypto.GenerateEd25519Key(bytes.NewReader(zeroBytes))

// Peer ID derived from the zero key
var zeroID, _ = peer.IDFromPublicKey(zeroKey.GetPublic())

func genClientID(t *testing.T) (peer.ID, crypto.PrivKey) {
	clientPrivStr, err := hex.DecodeString("080112407e0830617c4a7de83925dfb2694556b12936c477a0e1feb2e148ec9da60fee7d1ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e")
	require.NoError(t, err)
	clientKey, err := crypto.UnmarshalPrivateKey(clientPrivStr)
	require.NoError(t, err)
	clientID, err := peer.IDFromPrivateKey(clientKey)
	require.NoError(t, err)
	return clientID, clientKey
}
