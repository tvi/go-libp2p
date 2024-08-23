//go:build nocover

package httppeeridauth

import "testing"

func TestParsePeerIDAuthSchemeParamsNoAllocNoCover(t *testing.T) {
	str := []byte(`libp2p-PeerID peer-id="<server-peer-id-string>", sig="<base64-signature-bytes>", public-key="<base64-encoded-public-key-bytes>", bearer="<base64-encoded-opaque-blob>"`)
	paramMap := make(map[string][]byte, 5)

	allocs := testing.AllocsPerRun(1000, func() {
		paramMap, err := parsePeerIDAuthSchemeParams(str, paramMap)
		if err != nil {
			t.Fatal(err)
		}
		clear(paramMap)
	})
	if allocs > 0 {
		t.Fatalf("alloc test failed expected 0 received %0.2f", allocs)
	}
}
