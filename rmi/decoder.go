package rmi

import (
	"errors"
	"fmt"
	"io"

	"github.com/phith0n/zkar/commons"
)

// Decoder reads a JRMP byte stream frame-by-frame from an io.Reader (e.g. a
// live net.Conn). Unlike FromStream — which loops internally until the
// reader EOFs — Decoder returns each frame as soon as it's parsed, so
// callers can process one message before the next arrives, and can apply
// SetReadDeadline on the underlying net.Conn between calls to bound how
// long they wait for the next frame.
//
// Blocking semantics:
//
//   - CallMessage: the Registry dispatch gate fails fast for non-Registry
//     headers, and a valid Registry Call reads an exact arg count — Next()
//     returns as soon as the frame's own bytes arrive, even if the peer is
//     then silent.
//   - ReturnMessage: direction-agnostic parsing can't know whether a
//     NormalReturn's payload is 0 TCContents (void method: bind / rebind /
//     unbind) or 1 (list / lookup / any ExceptionalReturn), because that
//     depends on the originating Call. readReturn uses a sentinel peek
//     after the primitive header that blocks until one of: (a) the next
//     frame's flag byte arrives → current frame returns; (b) the peer
//     closes with io.EOF → current frame returns and the next Next()
//     returns io.EOF; (c) the reader's deadline fires → Next() returns
//     the deadline error.
//   - Ping / PingAck / DgcAck / handshake frames: all bounded, no
//     between-frame blocking.
//
// Callers that process Returns over a live connection should set
// SetReadDeadline on the underlying net.Conn.
//
// Typical usage:
//
//	d := rmi.NewDecoder(conn)
//	opening, err := d.Opening()          // optional; omit to skip
//	if err != nil { return err }
//	for {
//	    _ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
//	    msg, err := d.Next()
//	    if errors.Is(err, io.EOF) { break }
//	    if err != nil { return err }
//	    handle(msg)
//	}
type Decoder struct {
	stream      *commons.Stream
	openingDone bool
}

// NewDecoder returns a Decoder that reads from r. The Decoder holds the
// reader until its last frame is consumed or the caller drops it; the
// underlying bytes are only consumed on Opening() / Next() calls.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{stream: commons.NewStreamFromReader(r)}
}

// Opening reads the optional handshake-phase prefix: Handshake + client
// endpoint echo (client→server direction) or Acknowledge (server→client
// direction), or neither for a bare capture that starts mid-stream.
//
// Calling Opening is optional — if the caller omits it, the first Next()
// call will read and discard any opening transparently. Explicit Opening
// is the way to access the Handshake / Acknowledge / ClientEndpoint fields.
//
// It is an error to call Opening twice, or to call it after Next().
func (d *Decoder) Opening() (*Opening, error) {
	if d.openingDone {
		return nil, errors.New("rmi.Decoder: Opening already called")
	}
	d.openingDone = true
	var t Transmission
	if err := readOpening(d.stream, &t); err != nil {
		return nil, err
	}
	return &Opening{
		Handshake:      t.Handshake,
		Acknowledge:    t.Acknowledge,
		ClientEndpoint: t.ClientEndpoint,
	}, nil
}

// Next returns the next JRMP message. On the first call, if Opening hasn't
// been invoked, any handshake prefix is read and discarded. Returns io.EOF
// when the reader closes cleanly at a frame boundary. Non-Registry Calls
// error out at parse time; ReturnData may block on the sentinel peek
// between frames — see the Decoder doc for details.
func (d *Decoder) Next() (Message, error) {
	if !d.openingDone {
		var discard Transmission
		if err := readOpening(d.stream, &discard); err != nil {
			return nil, err
		}
		d.openingDone = true
	}
	if _, err := d.stream.PeekN(1); err != nil {
		// io.EOF flows through unwrapped so callers can check with
		// errors.Is(err, io.EOF); other errors (read timeouts, etc.)
		// are wrapped for context.
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("peek next message: %w", err)
	}
	return readMessage(d.stream)
}

// Opening captures the three optional handshake-phase fields of a JRMP
// Transmission. Any or all may be nil: client→server traffic typically sets
// Handshake + ClientEndpoint; server→client sets Acknowledge; a capture
// that starts mid-session sets none.
type Opening struct {
	Handshake      *Handshake
	Acknowledge    *Acknowledge
	ClientEndpoint *Endpoint
}
