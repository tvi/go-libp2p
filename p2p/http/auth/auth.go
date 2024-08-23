package httppeeridauth

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	logging "github.com/ipfs/go-log/v2"
	pool "github.com/libp2p/go-buffer-pool"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

const PeerIDAuthScheme = "libp2p-PeerID"

var PeerIDAuthSchemeBytes = []byte(PeerIDAuthScheme)

const bearerTokenPrefix = "bearer="
const ProtocolID = "/http-peer-id-auth/1.0.0"
const serverAuthPrefix = PeerIDAuthScheme + " challenge-client="
const challengeLen = 32

var log = logging.Logger("httppeeridauth")

func init() {
	sort.Strings(internedParamKeys)
}

var internedParamKeys []string = []string{
	"bearer",
	"challenge-client",
	"challenge-server",
	"opaque",
	"peer-id",
	"public-key",
	"sig",
}

const maxHeaderValSize = 2048

var errTooBig = errors.New("header value too big")
var errInvalid = errors.New("invalid header value")

// parsePeerIDAuthSchemeParams parses the parameters of the PeerID auth scheme
// from the header string. zero alloc if the params map is big enough.
func parsePeerIDAuthSchemeParams(headerVal []byte, params map[string][]byte) (map[string][]byte, error) {
	if len(headerVal) > maxHeaderValSize {
		return nil, errTooBig
	}
	startIdx := bytes.Index(headerVal, []byte(PeerIDAuthScheme))
	if startIdx == -1 {
		return params, nil
	}

	headerVal = headerVal[startIdx+len(PeerIDAuthScheme):]
	advance, token, err := splitAuthHeaderParams(headerVal, true)
	for ; err == nil; advance, token, err = splitAuthHeaderParams(headerVal, true) {
		headerVal = headerVal[advance:]
		bs := token
		splitAt := bytes.Index(bs, []byte("="))
		if splitAt == -1 {
			return nil, errInvalid
		}
		kB := bs[:splitAt]
		v := bs[splitAt+1:]
		i, ok := sort.Find(len(internedParamKeys), func(i int) int {
			return bytes.Compare(kB, []byte(internedParamKeys[i]))
		})
		var k string
		if ok {
			k = internedParamKeys[i]
		} else {
			// Not an interned key?
			k = string(kB)
		}

		params[k] = v
	}
	return params, nil
}

func splitAuthHeaderParams(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) == 0 && atEOF {
		return 0, nil, bufio.ErrFinalToken
	}

	start := 0
	for start < len(data) && (data[start] == ' ' || data[start] == ',') {
		start++
	}
	if start == len(data) {
		return len(data), nil, nil
	}
	end := start + 1
	for end < len(data) && data[end] != ' ' && data[end] != ',' {
		end++
	}
	token = data[start:end]
	if !bytes.ContainsAny(token, "=") {
		// This isn't a param. It's likely the next scheme. We're done
		return len(data), nil, bufio.ErrFinalToken
	}

	return end, token, nil
}

type authScheme struct {
	scheme      string
	params      map[string]string
	bearerToken string
}

const maxSchemes = 4
const maxParams = 10

var paramRegexStr = `([\w-]+)=([\w\d-_=.]+|"[^"]+")`
var paramRegex = regexp.MustCompile(paramRegexStr)

var authHeaderRegex = regexp.MustCompile(fmt.Sprintf(`(%s+\s+(:?(:?%s)(:?\s*,\s*)?)*)`, PeerIDAuthScheme, paramRegexStr))

func parseAuthHeader(headerVal string) (map[string]authScheme, error) {
	if len(headerVal) > maxAuthHeaderSize {
		return nil, fmt.Errorf("header too long")
	}
	schemes := authHeaderRegex.FindAllString(headerVal, maxSchemes+1)
	if len(schemes) > maxSchemes {
		return nil, fmt.Errorf("too many schemes")
	}

	if len(schemes) == 0 {
		return nil, nil
	}

	out := make([]authScheme, 0, 2)
	for _, s := range schemes {
		s = strings.TrimSpace(s)
		schemeEndIdx := strings.IndexByte(s, ' ')
		if schemeEndIdx == -1 {
			continue
		}
		scheme := authScheme{scheme: s[:schemeEndIdx]}
		switch scheme.scheme {
		case PeerIDAuthScheme:
		default:
			// Ignore unknown schemes
			continue
		}
		params := s[schemeEndIdx+1:]
		scheme.params = make(map[string]string, 10)
		params = strings.TrimSpace(params)
		for _, kv := range paramRegex.FindAllStringSubmatch(params, maxParams) {
			if len(kv) != 3 {
				return nil, fmt.Errorf("invalid param format")
			}
			scheme.params[kv[1]] = strings.Trim(kv[2], `"`)
		}
		out = append(out, scheme)
	}
	if len(out) == 0 {
		return nil, nil
	}

	outMap := make(map[string]authScheme, len(out))
	for _, s := range out {
		outMap[s.scheme] = s
	}
	return outMap, nil
}

func verifySig(publicKey crypto.PubKey, prefix string, signedParts []string, sig []byte) error {
	b := pool.Get(4096)
	defer pool.Put(b)
	buf, err := genDataToSign(b[:0], prefix, signedParts)
	if err != nil {
		return fmt.Errorf("failed to generate signed data: %w", err)
	}
	ok, err := publicKey.Verify(buf, sig)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func sign(privKey crypto.PrivKey, prefix string, partsToSign []string) ([]byte, error) {
	b := pool.Get(4096)
	defer pool.Put(b)
	buf, err := genDataToSign(b[:0], prefix, partsToSign)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data to sign: %w", err)
	}
	return privKey.Sign(buf)
}

func genDataToSign(buf []byte, prefix string, parts []string) ([]byte, error) {
	// Sort the parts in alphabetical order
	slices.Sort(parts)
	buf = append(buf, []byte(prefix)...)
	for _, p := range parts {
		buf = binary.AppendUvarint(buf, uint64(len(p)))
		buf = append(buf, p...)
	}
	return buf, nil
}

type authFields struct {
	hostname           string
	pubKey             crypto.PubKey
	opaque             string
	challengeServerB64 string
	challengeClientB64 string
	signature          []byte
}

func decodeB64PubKey(b64EncodedPubKey string) (crypto.PubKey, error) {
	bLen := base64.URLEncoding.DecodedLen(len(b64EncodedPubKey))
	buf := pool.Get(bLen)
	defer pool.Put(buf)

	buf, err := b64AppendDecode(buf[:0], []byte(b64EncodedPubKey))
	if err != nil {
		return nil, err
	}
	return crypto.UnmarshalPublicKey(buf)
}

func parseAuthFields(authHeader string, hostname string, isServer bool) (authFields, error) {
	if authHeader == "" {
		return authFields{}, errMissingAuthHeader
	}
	if len(authHeader) > maxAuthHeaderSize {
		return authFields{}, errors.New("authorization header too large")
	}

	schemes, err := parseAuthHeader(authHeader)
	if err != nil {
		return authFields{}, err
	}

	peerIDAuth, ok := schemes[PeerIDAuthScheme]
	if !ok {
		return authFields{}, errors.New("no peer ID auth scheme found")
	}

	if isServer && peerIDAuth.params["sig"] == "" {
		return authFields{}, errors.New("no signature found")
	}
	sig, err := base64.URLEncoding.DecodeString(peerIDAuth.params["sig"])
	if err != nil {
		return authFields{}, fmt.Errorf("failed to decode signature: %s", err)
	}

	var pubKey crypto.PubKey
	var id peer.ID
	if peerIDAuth.params["peer-id"] != "" {
		id, err = peer.Decode(peerIDAuth.params["peer-id"])
		if err != nil {
			return authFields{}, fmt.Errorf("failed to decode peer ID: %s", err)
		}
		pubKey, err = id.ExtractPublicKey()
		if err != nil && err != peer.ErrNoPublicKey {
			return authFields{}, err
		}
		if err == peer.ErrNoPublicKey {
			// RSA key perhaps, see if there is a public-key param
			encodedPubKey, ok := peerIDAuth.params["public-key"]
			if !ok {
				return authFields{}, errors.New("no public key found")
			}
			pubKey, err = decodeB64PubKey(encodedPubKey)
			if err != nil {
				return authFields{}, fmt.Errorf("failed to unmarshal public key: %s", err)
			}
			idFromKey, err := peer.IDFromPublicKey(pubKey)
			if err != nil {
				return authFields{}, fmt.Errorf("failed to get peer ID from public key: %s", err)
			}
			if id != idFromKey {
				return authFields{}, errors.New("peer ID from public key does not match peer ID")
			}
		} else {
			if encodedPubKey, ok := peerIDAuth.params["public-key"]; ok {
				// If there's a public key param, it must match the public key from the peer ID
				pubKeyFromParam, err := decodeB64PubKey(encodedPubKey)
				if err != nil {
					return authFields{}, fmt.Errorf("failed to unmarshal public key: %s", err)
				}
				if !pubKeyFromParam.Equals(pubKey) {
					return authFields{}, errors.New("public key from peer ID does not match public key from param")
				}
			}
		}
	}

	challengeServer := peerIDAuth.params["challenge-server"]

	var challengeClient string
	if !isServer {
		// Only parse this for the client. The server should read this from the opaque field
		challengeClient = peerIDAuth.params["challenge-client"]
	}

	return authFields{
		hostname:           hostname,
		pubKey:             pubKey,
		opaque:             peerIDAuth.params["opaque"],
		challengeServerB64: challengeServer,
		challengeClientB64: challengeClient,
		signature:          sig,
	}, nil
}

// Same as base64.URLEncoding.AppendEncode, but backported for Go 1.21. Once we are on Go 1.23 we can drop this
func b64AppendEncode(dst, src []byte) []byte {
	enc := base64.URLEncoding
	n := enc.EncodedLen(len(src))
	dst = slices.Grow(dst, n)
	enc.Encode(dst[len(dst):][:n], src)
	return dst[:len(dst)+n]
}

// Same as base64.URLEncoding.AppendDecode, but backported for Go 1.21. Once we are on Go 1.23 we can drop this
func b64AppendDecode(dst, src []byte) ([]byte, error) {
	enc := base64.URLEncoding
	encNoPad := base64.RawURLEncoding

	// Compute the output size without padding to avoid over allocating.
	n := len(src)
	for n > 0 && rune(src[n-1]) == base64.StdPadding {
		n--
	}
	n = encNoPad.DecodedLen(n)

	dst = slices.Grow(dst, n)
	n, err := enc.Decode(dst[len(dst):][:n], src)
	return dst[:len(dst)+n], err
}
