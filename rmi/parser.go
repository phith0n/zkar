package rmi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/phith0n/zkar/commons"
)

// Endpoint is one side's view of a TCP endpoint, written as
// DataOutput.writeUTF(host) + writeInt(port) on the raw stream (no
// ObjectOutputStream framing).
type Endpoint struct {
	Host string
	Port int32
}

// Transmission is a parsed JRMP byte stream from either direction of a
// Stream-protocol connection. The three opening fields capture the handshake
// phase — any or all can be nil depending on which side of the conversation
// the caller captured, and whether the capture starts at the handshake or
// mid-stream.
//
//   - Handshake: present when the bytes start with "JRMI" (client→server).
//   - Acknowledge: present when the bytes start with 0x4E (server→client).
//   - ClientEndpoint: client's own endpoint suggestion sent immediately
//     after its handshake. Only meaningful when Handshake != nil.
type Transmission struct {
	Handshake      *Handshake
	Acknowledge    *Acknowledge
	ClientEndpoint *Endpoint
	Messages       []Message
}

// FromBytes parses a fully-buffered JRMP byte slice (a .ser-style capture,
// an io.ReadAll result, etc.). The parser loops readMessage until io.EOF,
// returning the full Transmission.
func FromBytes(data []byte) (*Transmission, error) {
	return parseTransmission(commons.NewStream(data))
}

// FromStream parses JRMP traffic from an io.Reader (net.Conn, io.Pipe, etc.)
// without io.ReadAll-ing the whole stream first. It loops readMessage until
// the reader returns io.EOF.
//
// Blocking semantics: the message loop blocks on the reader between frames.
// Call frames are exact-count (Registry fast path) and return as soon as
// their bytes arrive; ReturnData uses a sentinel that blocks after the
// primitive header until the next frame's flag byte arrives, the peer
// closes (io.EOF), or the reader's deadline fires. Non-Registry Call
// headers fail fast — this parser only handles Registry stubs.
//
// For live TCP servers that need to process frames as they arrive — or for
// any caller that wants to apply a SetReadDeadline between frames — use
// Decoder instead; its Next() method returns one message at a time.
func FromStream(r io.Reader) (*Transmission, error) {
	return parseTransmission(commons.NewStreamFromReader(r))
}

// parseTransmission is the single implementation behind both FromBytes and
// FromStream.
func parseTransmission(stream *commons.Stream) (*Transmission, error) {
	t := &Transmission{}
	if err := readOpening(stream, t); err != nil {
		return nil, err
	}

	// Message loop until EOF.
	for {
		_, err := stream.PeekN(1)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return t, nil
			}
			return nil, fmt.Errorf("peek next message: %w", err)
		}
		msg, merr := readMessage(stream)
		if merr != nil {
			return nil, merr
		}
		t.Messages = append(t.Messages, msg)
	}
}

// readOpening consumes the optional handshake-phase prefix (handshake OR
// acknowledge, plus the client's endpoint echo when a handshake is present).
// It peeks the first byte to decide what — if anything — precedes the
// message loop. Populates the given Transmission's Handshake / Acknowledge /
// ClientEndpoint fields in place. An empty (EOF) stream is a (degenerate)
// valid Transmission and leaves t untouched.
func readOpening(stream *commons.Stream, t *Transmission) error {
	first, err := stream.PeekN(1)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("peek first byte: %w", err)
	}

	switch first[0] {
	case JRMI_MAGIC[0]: // 0x4A — client→server handshake
		h, herr := readHandshake(stream)
		if herr != nil {
			return herr
		}
		t.Handshake = h

		// A conforming Stream-protocol client immediately follows the
		// 7-byte handshake with its own endpoint suggestion. Some
		// hand-crafted fixtures skip this; peek and decide.
		ep, eerr := maybeReadClientEndpoint(stream)
		if eerr != nil {
			return fmt.Errorf("client endpoint echo: %w", eerr)
		}
		t.ClientEndpoint = ep

	case AckFlag: // 0x4E — server→client ProtocolAck
		a, aerr := readAcknowledge(stream)
		if aerr != nil {
			return aerr
		}
		t.Acknowledge = a

		// No further server-side echo: Acknowledge already carries
		// the server's view of the client endpoint.
	}
	return nil
}

// maybeReadClientEndpoint reads the client's post-handshake endpoint echo
// (UTF host + int32 port) when present. If the next byte is a JRMP message
// flag, we assume the capture omits the echo and return nil. Hostnames are
// never long enough for their UTF length prefix to collide with the
// [0x50, 0x54] message-flag range (which would require ≥ 20480-char hosts).
func maybeReadClientEndpoint(stream *commons.Stream) (*Endpoint, error) {
	next, err := stream.PeekN(1)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}
	if next[0] >= MsgCall && next[0] <= MsgDgcAck {
		return nil, nil
	}
	host, err := readModifiedUTF(stream)
	if err != nil {
		return nil, err
	}
	portBs, err := stream.ReadN(4)
	if err != nil {
		return nil, fmt.Errorf("read endpoint port on index %v: %w", stream.CurrentIndex(), err)
	}
	return &Endpoint{
		Host: host,
		Port: int32(binary.BigEndian.Uint32(portBs)),
	}, nil
}

func (t *Transmission) ToString() string {
	b := commons.NewPrinter()
	b.Printf("JRMP Transmission")
	b.IncreaseIndent()
	if t.Handshake != nil {
		b.Print(t.Handshake.ToString())
	}
	if t.Acknowledge != nil {
		b.Print(t.Acknowledge.ToString())
	}
	if t.ClientEndpoint != nil {
		b.Printf("@ClientEndpoint")
		b.IncreaseIndent()
		b.Printf("@Host")
		b.IncreaseIndent()
		b.Printf("@Length - %d - %s", len(t.ClientEndpoint.Host), commons.Hexify(uint16(len(t.ClientEndpoint.Host))))
		b.Printf("@Value - %s - %s", t.ClientEndpoint.Host, commons.Hexify(t.ClientEndpoint.Host))
		b.DecreaseIndent()
		b.Printf("@Port - %d - %s", t.ClientEndpoint.Port, commons.Hexify(t.ClientEndpoint.Port))
		b.DecreaseIndent()
	}
	if len(t.Messages) > 0 {
		b.Printf("@Messages")
		b.IncreaseIndent()
		for _, msg := range t.Messages {
			b.Print(msg.ToString())
		}
	}
	return b.String()
}
