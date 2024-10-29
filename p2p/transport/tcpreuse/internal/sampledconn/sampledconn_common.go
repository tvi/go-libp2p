package sampledconn

import (
	"io"
	"net"
	"time"
)

const sampleSize = 3

type fallbackSampledConn struct {
	tcpConnInterface
	Sample         [sampleSize]byte
	readFromSample uint8
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

func newFallbackSampledConn(conn tcpConnInterface) (*fallbackSampledConn, error) {
	s := &fallbackSampledConn{tcpConnInterface: conn}
	_, err := io.ReadFull(conn, s.Sample[:])
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (sc *fallbackSampledConn) Read(b []byte) (int, error) {
	if int(sc.readFromSample) != len(sc.Sample) {
		red := copy(b, sc.Sample[sc.readFromSample:])
		sc.readFromSample += uint8(red)
		return red, nil
	}

	return sc.tcpConnInterface.Read(b)
}
