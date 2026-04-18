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
// Blocking semantics: Decoder is subject to the same between-frame peek
// that FromStream is. The Registry fast path (matching ObjID + interface
// hash + known op-index) reads an exact arg count and returns as soon as
// its own bytes arrive. A non-Registry Call or a ReturnData uses a sentinel
// peek after its last arg/payload that blocks until one of:
//
//   - the next frame's flag byte arrives → current frame returns
//   - the peer closes the connection → current frame returns; the NEXT
//     Next() call returns io.EOF
//   - the reader's deadline fires → Next() returns the deadline error;
//     the parse state is preserved, so after SetReadDeadline is extended
//     the caller MAY retry. In practice most deadline errors from net.Conn
//     are terminal (the timeout unblocks all outstanding reads); retry is
//     only safe if you can reason about your deadline/connection state.
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
// when the reader closes cleanly at a frame boundary. For non-Registry
// Calls and ReturnData, see the Decoder doc for blocking semantics.
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
