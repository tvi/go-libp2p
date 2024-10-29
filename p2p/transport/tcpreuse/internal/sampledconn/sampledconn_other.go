//go:build !unix

package sampledconn

type SampledConn = *fallbackSampledConn

func NewSampledConn(conn tcpConnInterface) (SampledConn, error) {
	return newFallbackSampledConn(conn)
}
