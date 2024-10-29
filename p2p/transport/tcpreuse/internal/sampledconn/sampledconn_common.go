package sampledconn

import (
	"errors"
	"io"
	"net"
	"syscall"
	"time"
)

const peekSize = 3

type PeekedBytes = [peekSize]byte

var errNotSupported = errors.New("not supported on this platform")

var ErrNotTCPConn = errors.New("passed conn is not a TCPConn")

func PeekBytes(conn net.Conn) (PeekedBytes, net.Conn, error) {
	if c, ok := conn.(syscall.Conn); ok {
		b, err := OSPeekConn(c)
		if err == nil {
			return b, conn, nil
		}
		if err != errNotSupported {
			return PeekedBytes{}, nil, err
		}
		// Fallback to wrapping the coonn
	}

	if c, ok := conn.(tcpConnInterface); ok {
		return newFallbackSampledConn(c)
	}

	return PeekedBytes{}, nil, ErrNotTCPConn
}

type fallbackPeekingConn struct {
	tcpConnInterface
	peekedBytes PeekedBytes
	bytesPeeked uint8
}

// tcpConnInterface is the interface for TCPConn's functions
// NOTE: Skipping `SyscallConn() (syscall.RawConn, error)` since it can be
// misused given we've read a few bytes from the connection.
type tcpConnInterface interface {
	net.Conn

	CloseRead() error
	CloseWrite() error

	SetLinger(sec int) error
	SetKeepAlive(keepalive bool) error
	SetKeepAlivePeriod(d time.Duration) error
	SetNoDelay(noDelay bool) error
	MultipathTCP() (bool, error)

	io.ReaderFrom
	io.WriterTo
}

func newFallbackSampledConn(conn tcpConnInterface) (PeekedBytes, *fallbackPeekingConn, error) {
	s := &fallbackPeekingConn{tcpConnInterface: conn}
	_, err := io.ReadFull(conn, s.peekedBytes[:])
	if err != nil {
		return s.peekedBytes, nil, err
	}
	return s.peekedBytes, s, nil
}

func (sc *fallbackPeekingConn) Read(b []byte) (int, error) {
	if int(sc.bytesPeeked) != len(sc.peekedBytes) {
		red := copy(b, sc.peekedBytes[sc.bytesPeeked:])
		sc.bytesPeeked += uint8(red)
		return red, nil
	}

	return sc.tcpConnInterface.Read(b)
}
