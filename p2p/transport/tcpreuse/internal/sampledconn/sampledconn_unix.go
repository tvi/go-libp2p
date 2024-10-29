//go:build unix

package sampledconn

import (
	"errors"
	"net"
	"syscall"
)

type SampledConn struct {
	*net.TCPConn
	Sample [sampleSize]byte
}

func NewSampledConn(conn *net.TCPConn) (SampledConn, error) {
	s := SampledConn{
		TCPConn: conn,
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return s, err
	}

	readBytes := 0
	var readErr error
	err = rawConn.Read(func(fd uintptr) bool {
		for readBytes < sampleSize {
			var n int
			n, _, readErr = syscall.Recvfrom(int(fd), s.Sample[readBytes:], syscall.MSG_PEEK)
			if errors.Is(readErr, syscall.EAGAIN) {
				return false
			}
			if readErr != nil {
				return true
			}
			readBytes += n
		}
		return true
	})
	if readErr != nil {
		return s, readErr
	}
	if err != nil {
		return s, err
	}

	return s, nil
}
