package sampledconn

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSampledConn(t *testing.T) {
	testCases := []string{
		"platform",
		// "fallback",
	}

	// Start a TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Server goroutine
	go func() {
		conn, err := listener.Accept()
		assert.NoError(t, err)
		defer conn.Close()

		// Write some data to the connection
		_, err = conn.Write([]byte("hello"))
		assert.NoError(t, err)
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			// Create a TCP client
			clientConn, err := net.Dial("tcp", serverAddr)
			assert.NoError(t, err)
			defer clientConn.Close()

			if tc == "platform" {
				// Wrap the client connection in SampledConn
				sampledConn, err := NewSampledConn(clientConn.(*net.TCPConn))
				assert.NoError(t, err)
				assert.Equal(t, "hel", string(sampledConn.Sample[:]))

				buf := make([]byte, 5)
				_, err = sampledConn.Read(buf)
				assert.NoError(t, err)
				assert.Equal(t, "hello", string(buf))
			} else {
				// Wrap the client connection in SampledConn
				sampledConn, err := newFallbackSampledConn(clientConn.(tcpConnInterface))
				assert.NoError(t, err)
				assert.Equal(t, "hel", string(sampledConn.Sample[:]))

				buf := make([]byte, 5)
				_, err = io.ReadFull(sampledConn, buf)
				assert.NoError(t, err)
				assert.Equal(t, "hello", string(buf))

			}
		})
	}
}
