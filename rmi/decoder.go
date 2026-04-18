package rmi

import (
	"errors"
	"fmt"
	"io"

	"github.com/phith0n/zkar/commons"
)

// Decoder reads a JRMP byte stream frame-by-frame from an io.Reader (e.g. a
// live net.Conn). It's the only supported way to parse from a long-lived
// TCP connection: FromBytes needs the whole capture in a []byte, and a
// message-loop-until-EOF would deadlock between frames because the peer
// typically keeps the connection open waiting for a reply before sending
// anything else.
//
// Decoder returns each frame as soon as it's parsed, so callers can process
// one message before the next arrives and can apply SetReadDeadline on the
// underlying net.Conn between calls to bound how long they wait.
//
// # Opening-phase primitives vs. Opening()
//
// The JRMP opening has three pieces that are interleaved with a server-side
// write on the wire:
//
//	client → server:  JRMI magic + version + 0x4B             (7 bytes)
//	server → client:  0x4E + writeUTF(host) + int32(port)     (Acknowledge)
//	client → server:  writeUTF(host) + int32(port)            (ClientEndpoint)
//
// A conforming Java client blocks after sending the handshake until the
// server's Acknowledge arrives, and only then writes its ClientEndpoint.
// That means Opening() — which reads Handshake+ClientEndpoint in one call —
// deadlocks on a server-side reader: the second PeekN waits for bytes the
// client will not send until it has received the Ack.
//
// For server-side use (or any caller that needs to inject a write between
// the handshake reads), use the fine-grained primitives:
//
//	ReadHandshake()        — consumes only the 7-byte handshake
//	ReadClientEndpoint()   — consumes the post-Ack endpoint echo
//	ReadAcknowledge()      — consumes the server→client Acknowledge frame
//
// Opening() remains the convenience entry point for fully-buffered captures
// and for client→server consumers that already have the bytes in hand.
//
// # Blocking semantics
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
// # Typical usage
//
// Client → server capture (bytes already in hand):
//
//	d := rmi.NewDecoder(bytes.NewReader(data))
//	opening, err := d.Opening()
//	if err != nil { return err }
//	for {
//	    msg, err := d.Next()
//	    if errors.Is(err, io.EOF) { break }
//	    if err != nil { return err }
//	    handle(msg)
//	}
//
// Server side on a live net.Conn:
//
//	d := rmi.NewDecoder(conn)
//	hs, err := d.ReadHandshake()
//	if err != nil { return err }
//	remote := conn.RemoteAddr().(*net.TCPAddr)
//	ack := &rmi.Acknowledge{Host: remote.IP.String(), Port: int32(remote.Port)}
//	if _, err := conn.Write(ack.ToBytes()); err != nil { return err }
//	ep, err := d.ReadClientEndpoint()
//	if err != nil { return err }
//	for {
//	    _ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
//	    msg, err := d.Next()
//	    if errors.Is(err, io.EOF) { break }
//	    if err != nil { return err }
//	    handle(msg)
//	}
type Decoder struct {
	stream *commons.Stream
	stage  decoderStage
}

// decoderStage tracks how far through the opening phase the Decoder has
// progressed. Each Read* primitive and Opening() check this before
// advancing it; Next() refuses to run until the stage reaches stageReady.
type decoderStage int

const (
	stageInitial        decoderStage = iota // nothing consumed yet
	stageAfterHandshake                     // 7-byte handshake consumed; ClientEndpoint still pending
	stageReady                              // opening phase done; Next() is the only valid call
)

// NewDecoder returns a Decoder that reads from r. The Decoder holds the
// reader until its last frame is consumed or the caller drops it; the
// underlying bytes are only consumed on Opening() / Next() calls.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{stream: commons.NewStreamFromReader(r)}
}

// Opening reads the optional handshake-phase prefix in one call: Handshake +
// client endpoint echo (client→server direction) or Acknowledge
// (server→client direction), or neither for a bare capture that starts
// mid-stream.
//
// Opening is a convenience entry point for fully-buffered captures and
// consumers that already have every byte. It is NOT safe on a server-side
// live reader: a conforming client sends its handshake and then blocks
// waiting for the server's Acknowledge, so the peek inside
// maybeReadClientEndpoint deadlocks. Servers must use ReadHandshake +
// ReadClientEndpoint with their own Acknowledge write in between.
//
// Calling Opening is optional — if the caller omits it, the first Next()
// call will read and discard any opening transparently. Explicit Opening
// is the way to access the Handshake / Acknowledge / ClientEndpoint fields.
//
// It is an error to call Opening twice, after Next(), or after any of the
// ReadHandshake / ReadClientEndpoint / ReadAcknowledge primitives.
func (d *Decoder) Opening() (*Opening, error) {
	if d.stage != stageInitial {
		return nil, errors.New("rmi.Decoder: Opening is only valid as the first call")
	}
	var t Transmission
	if err := readOpening(d.stream, &t); err != nil {
		return nil, err
	}
	d.stage = stageReady
	return &Opening{
		Handshake:      t.Handshake,
		Acknowledge:    t.Acknowledge,
		ClientEndpoint: t.ClientEndpoint,
	}, nil
}

// ReadHandshake consumes the 7-byte client→server opening
// (JRMI magic + uint16 version + 1-byte sub-protocol flag) and nothing else.
// This is the first call a server should make after accepting a connection:
// it returns as soon as the 7 bytes arrive, leaving the server free to
// write its Acknowledge before reading the ClientEndpoint echo. Call
// ReadClientEndpoint (or Next, which consumes any remaining opening
// implicitly) once the Ack has been written.
//
// It is an error to call ReadHandshake after Opening, any other Read*
// primitive, or Next.
func (d *Decoder) ReadHandshake() (*Handshake, error) {
	if d.stage != stageInitial {
		return nil, errors.New("rmi.Decoder: ReadHandshake must be the first call")
	}
	h, err := readHandshake(d.stream)
	if err != nil {
		return nil, err
	}
	d.stage = stageAfterHandshake
	return h, nil
}

// ReadClientEndpoint consumes the client's post-Acknowledge endpoint echo
// (writeUTF host + int32 port). Must be preceded by ReadHandshake; the
// server is expected to have written its Acknowledge between the two
// calls. Returns (nil, nil) if the client omits the echo (matching the
// lenient behavior of fully-buffered captures).
//
// It is an error to call ReadClientEndpoint outside the
// ReadHandshake → ReadClientEndpoint sequence.
func (d *Decoder) ReadClientEndpoint() (*Endpoint, error) {
	if d.stage != stageAfterHandshake {
		return nil, errors.New("rmi.Decoder: ReadClientEndpoint must follow ReadHandshake")
	}
	ep, err := maybeReadClientEndpoint(d.stream)
	if err != nil {
		return nil, fmt.Errorf("client endpoint echo: %w", err)
	}
	d.stage = stageReady
	return ep, nil
}

// ReadAcknowledge consumes the server→client Acknowledge frame
// (0x4E + writeUTF host + int32 port). This is the primitive a client-side
// reader uses to inspect the server's view of its endpoint before any
// message traffic. Must be the first call on the Decoder.
//
// It is an error to call ReadAcknowledge after Opening, any other Read*
// primitive, or Next.
func (d *Decoder) ReadAcknowledge() (*Acknowledge, error) {
	if d.stage != stageInitial {
		return nil, errors.New("rmi.Decoder: ReadAcknowledge must be the first call")
	}
	a, err := readAcknowledge(d.stream)
	if err != nil {
		return nil, err
	}
	d.stage = stageReady
	return a, nil
}

// Next returns the next JRMP message. On the first call, if no opening
// primitive has advanced the Decoder past stageReady, any remaining
// handshake-phase bytes are read and discarded — including a lone
// ClientEndpoint when ReadHandshake was called but ReadClientEndpoint was
// skipped. Returns io.EOF when the reader closes cleanly at a frame
// boundary. Non-Registry Calls error out at parse time; ReturnData may
// block on the sentinel peek between frames — see the Decoder doc for
// details.
func (d *Decoder) Next() (Message, error) {
	if d.stage != stageReady {
		if err := d.finishOpening(); err != nil {
			return nil, err
		}
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

// finishOpening fast-forwards from whichever stage the caller left the
// Decoder in to stageReady, consuming only the bytes the remaining opening
// phase owns. It exists so Next() can be called on a Decoder whose caller
// didn't (or couldn't) explicitly finish the opening.
func (d *Decoder) finishOpening() error {
	switch d.stage {
	case stageInitial:
		var discard Transmission
		if err := readOpening(d.stream, &discard); err != nil {
			return err
		}
	case stageAfterHandshake:
		if _, err := maybeReadClientEndpoint(d.stream); err != nil {
			return fmt.Errorf("client endpoint echo: %w", err)
		}
	}
	d.stage = stageReady
	return nil
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
