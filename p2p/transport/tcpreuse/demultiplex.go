package tcpreuse

import (
	"bufio"
	"errors"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/p2p/transport/tcpreuse/internal/sampledconn"
	manet "github.com/multiformats/go-multiaddr/net"
)

type peekAble interface {
	// Peek returns the next n bytes without advancing the reader. The bytes stop
	// being valid at the next read call. If Peek returns fewer than n bytes, it
	// also returns an error explaining why the read is short. The error is
	// [ErrBufferFull] if n is larger than b's buffer size.
	Peek(n int) ([]byte, error)
}

var _ peekAble = (*bufio.Reader)(nil)

// TODO: We can unexport this type and rely completely on the multiaddr passed in to
// DemultiplexedListen.
type DemultiplexedConnType int

const (
	DemultiplexedConnType_Unknown DemultiplexedConnType = iota
	DemultiplexedConnType_MultistreamSelect
	DemultiplexedConnType_HTTP
	DemultiplexedConnType_TLS
)

func (t DemultiplexedConnType) String() string {
	switch t {
	case DemultiplexedConnType_MultistreamSelect:
		return "MultistreamSelect"
	case DemultiplexedConnType_HTTP:
		return "HTTP"
	case DemultiplexedConnType_TLS:
		return "TLS"
	default:
		return fmt.Sprintf("Unknown(%d)", int(t))
	}
}

func (t DemultiplexedConnType) IsKnown() bool {
	return t >= 1 || t <= 3
}

// identifyConnType attempts to identify the connection type by peeking at the
// first few bytes.
// It Callers must not use the passed in Conn after this
// function returns. if an error is returned, the connection will be closed.
func identifyConnType(c manet.Conn) (DemultiplexedConnType, manet.Conn, error) {
	if err := c.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		closeErr := c.Close()
		return 0, nil, errors.Join(err, closeErr)
	}

	s, c, err := sampledconn.PeekBytes(c)
	if err != nil {
		closeErr := c.Close()
		return 0, nil, errors.Join(err, closeErr)
	}

	if err := c.SetReadDeadline(time.Time{}); err != nil {
		closeErr := c.Close()
		return 0, nil, errors.Join(err, closeErr)
	}

	if IsMultistreamSelect(s) {
		return DemultiplexedConnType_MultistreamSelect, c, nil
	}
	if IsTLS(s) {
		return DemultiplexedConnType_TLS, c, nil
	}
	if IsHTTP(s) {
		return DemultiplexedConnType_HTTP, c, nil
	}
	return DemultiplexedConnType_Unknown, c, nil
}

// Matchers are implemented here instead of in the transports so we can easily fuzz them together.
type Prefix = [3]byte

func IsMultistreamSelect(s Prefix) bool {
	return string(s[:]) == "\x13/m"
}

func IsHTTP(s Prefix) bool {
	switch string(s[:]) {
	case "GET", "HEA", "POS", "PUT", "DEL", "CON", "OPT", "TRA", "PAT":
		return true
	default:
		return false
	}
}

func IsTLS(s Prefix) bool {
	switch string(s[:]) {
	case "\x16\x03\x01", "\x16\x03\x02", "\x16\x03\x03", "\x16\x03\x04":
		return true
	default:
		return false
	}
}
