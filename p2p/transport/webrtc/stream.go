package libp2pwebrtc

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/transport/webrtc/internal/async"
	pb "github.com/libp2p/go-libp2p/p2p/transport/webrtc/pb"
	"github.com/libp2p/go-msgio/pbio"
	"github.com/pion/datachannel"
	"github.com/pion/webrtc/v3"
)

var _ network.MuxedStream = &webRTCStream{}

const (
	// maxMessageSize is limited to 16384 bytes in the SDP.
	maxMessageSize = 16384
	// Pion SCTP association has an internal receive buffer of 1MB (roughly, 1MB per connection).
	// We can change this value in the SettingEngine before creating the peerconnection.
	// https://github.com/pion/webrtc/blob/v3.1.49/sctptransport.go#L341
	maxBufferedAmount = 2 * maxMessageSize
	// bufferedAmountLowThreshold and maxBufferedAmount are bound
	// to a stream but congestion control is done on the whole
	// SCTP association. This means that a single stream can monopolize
	// the complete congestion control window (cwnd) if it does not
	// read stream data and it's remote continues to send. We can
	// add messages to the send buffer once there is space for 1 full
	// sized message.
	bufferedAmountLowThreshold = maxBufferedAmount / 2

	// Proto overhead assumption is 5 bytes
	protoOverhead = 5
	// Varint overhead is assumed to be 2 bytes. This is safe since
	// 1. This is only used and when writing message, and
	// 2. We only send messages in chunks of `maxMessageSize - varintOverhead`
	// which includes the data and the protobuf header. Since `maxMessageSize`
	// is less than or equal to 2 ^ 14, the varint will not be more than
	// 2 bytes in length.
	varintOverhead = 2
)

// Package pion detached data channel into a net.Conn
// and then a network.MuxedStream
type webRTCStream struct {
	reader pbio.Reader
	// pbio.Reader is not thread safe,
	// and while our Read is not promised to be thread safe,
	// we ourselves internally read from multiple routines...
	readerMux  sync.Mutex
	readBuffer []byte

	writer pbio.Writer
	// public write API is not promised to be thread safe, however we also write from
	// read functionality due to our spec limiations, so (e.g. 1 channel for state and data)
	// and thus we do need to protect the writer
	writerMux sync.Mutex

	writerDeadline    time.Time
	writerDeadlineMux sync.Mutex

	writerDeadlineUpdated async.CondVar
	writeAvailable        async.CondVar

	readLoopOnce sync.Once

	stateHandler webRTCStreamState

	// hack for closing the Read side using a deadline
	// in case `Read` does not return.
	closeErr    error
	closeErrMux sync.Mutex

	conn *connection
	id   uint16
	rwc  datachannel.ReadWriteCloser

	laddr net.Addr
	raddr net.Addr

	ctx    context.Context
	cancel context.CancelFunc

	closeOnce sync.Once
}

func newStream(
	connection *connection,
	channel *webrtc.DataChannel,
	rwc datachannel.ReadWriteCloser,
	laddr, raddr net.Addr,
) *webRTCStream {
	ctx, cancel := context.WithCancel(context.Background())

	// allocating 16KiB per stream might seem wasteful,
	// but problem is that we also write max up to this amount,
	// and pion does not allow us to read chunks. Should you try to do so,
	// and you read less then that there's written you'll notice
	// undefined behaviour where the unread part is dropped.
	reader := bufio.NewReaderSize(rwc, maxMessageSize)

	result := &webRTCStream{
		reader: pbio.NewDelimitedReader(reader, maxMessageSize),
		writer: pbio.NewDelimitedWriter(rwc),

		conn: connection,
		id:   *channel.ID(),
		rwc:  rwc,

		laddr: laddr,
		raddr: raddr,

		ctx:    ctx,
		cancel: cancel,
	}

	channel.SetBufferedAmountLowThreshold(bufferedAmountLowThreshold)
	channel.OnBufferedAmountLow(func() {
		result.writeAvailable.Signal()
	})

	return result
}

func (s *webRTCStream) Close() error {
	return s.close(false, true)
}

func (s *webRTCStream) Reset() error {
	return s.close(true, true)
}

func (s *webRTCStream) LocalAddr() net.Addr {
	return s.laddr
}

func (s *webRTCStream) RemoteAddr() net.Addr {
	return s.raddr
}

func (s *webRTCStream) SetDeadline(t time.Time) error {
	return s.SetWriteDeadline(t)
}

func (s *webRTCStream) processIncomingFlag(flag pb.Message_Flag) {
	if s.isClosed() {
		return
	}
	state, reset := s.stateHandler.HandleInboundFlag(flag)
	if state == stateClosed {
		log.Debug("closing: after handle inbound flag")
		s.close(reset, true)
	}
}

func (s *webRTCStream) setCloseErrIfUndefined(isReset bool) {
	s.closeErrMux.Lock()
	defer s.closeErrMux.Unlock()
	if s.closeErr == nil {
		s.closeErr = io.EOF
		if isReset {
			s.closeErr = io.ErrClosedPipe
		}
	}
}

func (s *webRTCStream) getCloseErr() error {
	s.closeErrMux.Lock()
	defer s.closeErrMux.Unlock()
	return s.closeErr
}

// this is used to force reset a stream
func (s *webRTCStream) close(isReset bool, notifyConnection bool) error {
	if s.isClosed() {
		return nil
	}

	var err error
	s.closeOnce.Do(func() {
		log.Debug("closing: reset: %v, notify: %v", isReset, notifyConnection)
		s.stateHandler.Close()
		s.setCloseErrIfUndefined(isReset)
		// force close reads
		s.SetReadDeadline(time.Now()) // pion ignores zero times
		if isReset {
			// write the RESET message. The error is explicitly ignored
			// because we do not know if the remote is still connected
			s.writeMessage(&pb.Message{Flag: pb.Message_RESET.Enum()})
		} else {
			// write a FIN message for standard stream closure
			s.writeMessage(&pb.Message{Flag: pb.Message_FIN.Enum()})
		}
		// close the context
		s.cancel()
		// close the channel. We do not care about the error message in
		// this case
		err = s.rwc.Close()
		if notifyConnection && s.conn != nil {
			s.conn.removeStream(s.id)
		}
	})

	return err
}

func (s *webRTCStream) isClosed() bool {
	select {
	case <-s.ctx.Done():
		return true
	default:
		return false
	}
}