package httppeeridauth

import (
	"bytes"
	"crypto/rand"
	"net/http"
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
					PrivKey: serverKey,
					ValidHostnameFn: func(s string) bool {
						return s == "example.com"
					},
					TokenTTL:      time.Hour,
					InsecureNoTLS: true,
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
					PrivKey: serverKey,
					ValidHostnameFn: func(s string) bool {
						return s == "example.com"
					},
					TokenTTL: time.Hour,
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
				ts, _ := stc.serverGen(t)
				client := ts.Client()
				tlsClientConfig := client.Transport.(*http.Transport).TLSClientConfig
				if tlsClientConfig != nil {
					// If we're using TLS, we need to set the SNI so that the
					// server can verify the request Host matches it.
					tlsClientConfig.ServerName = "example.com"
				}
				clientKey := ctc.clientKeyGen(t)
				clientAuth := ClientPeerIDAuth{PrivKey: clientKey}

				expectedServerID, err := peer.IDFromPrivateKey(serverKey)
				require.NoError(t, err)

				req, err := http.NewRequest("POST", ts.URL, nil)
				require.NoError(t, err)
				req.Host = "example.com"
				serverID, resp, err := clientAuth.AuthenticatedDo(client, req)
				require.NoError(t, err)
				require.Equal(t, expectedServerID, serverID)
				require.NotZero(t, clientAuth.tokenMap["example.com"])
				require.Equal(t, http.StatusOK, resp.StatusCode)

				// Once more with the auth token
				req, err = http.NewRequest("POST", ts.URL, nil)
				require.NoError(t, err)
				req.Host = "example.com"
				serverID, resp, err = clientAuth.AuthenticatedDo(client, req)
				require.NotEmpty(t, req.Header.Get("Authorization"))
				require.NoError(t, err)
				require.Equal(t, expectedServerID, serverID)
				require.NotZero(t, clientAuth.tokenMap["example.com"])
				require.Equal(t, http.StatusOK, resp.StatusCode)
			})
		}
	}
}

// // Test Vectors
// var zeroBytes = make([]byte, 64)
// var zeroKey, _, _ = crypto.GenerateEd25519Key(bytes.NewReader(zeroBytes))

// // Peer ID derived from the zero key
// var zeroID, _ = peer.IDFromPublicKey(zeroKey.GetPublic())

// TODO add generator for specs table & example
