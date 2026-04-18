package rmi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/phith0n/zkar/commons"
)

// Entry points:
//
//   - FromBytes — parse a fully-buffered JRMP capture (bytes read from a
//     .bin file, an http.Response body you've ReadAll'd, etc.). Loops until
//     io.EOF and returns the whole Transmission.
//   - Decoder (rmi/decoder.go) — read one frame at a time from any
//     io.Reader. The only sensible choice for a live net.Conn: FromBytes
//     needs the bytes in advance, and a message-loop over a live reader
//     would deadlock on the first PeekN(1) between frames (the peer is
//     typically waiting for a reply and sends nothing).

// Endpoint is one side's view of a TCP endpoint, written as
// DataOutput.writeUTF(host) + writeInt(port) on the raw stream (no
// ObjectOutputStream framing).
type Endpoint struct {
	Host string
	Port int32
}

// ToBytes encodes the endpoint as writeUTF(host) + int32(port) — the exact
// layout a client writes immediately after receiving the server's
// Acknowledge, and the layout ReadClientEndpoint consumes.
func (e *Endpoint) ToBytes() []byte {
	var buf bytes.Buffer
	writeModifiedUTF(&buf, e.Host)
	_ = binary.Write(&buf, binary.BigEndian, e.Port)
	return buf.Bytes()
}

// ToString formats the endpoint as a wireshark-dissector-style block
// headed by "@Endpoint", matching the style of Handshake/Acknowledge.
func (e *Endpoint) ToString() string {
	b := commons.NewPrinter()
	b.Printf("@Endpoint")
	b.IncreaseIndent()
	b.Printf("@Host")
	b.IncreaseIndent()
	b.Printf("@Length - %d - %s", len(e.Host), commons.Hexify(uint16(len(e.Host))))
	b.Printf("@Value - %s - %s", e.Host, commons.Hexify(e.Host))
	b.DecreaseIndent()
	b.Printf("@Port - %d - %s", e.Port, commons.Hexify(e.Port))
	return b.String()
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

// FromBytes parses a fully-buffered JRMP byte slice (a .bin capture, an
// io.ReadAll result, etc.). Reads frames until io.EOF and returns the
// whole Transmission.
//
// Not suitable for a live net.Conn: after the last frame of a typical
// request/response the peer keeps the connection open waiting for the
// reply, and the loop would block forever on the next PeekN. Use Decoder
// directly for live connections.
//
// Implementation-wise this is a thin wrapper over Decoder — Decoder is the
// single primitive that owns the readMessage loop, FromBytes just drains
// it to EOF and reassembles the Transmission struct.
func FromBytes(data []byte) (*Transmission, error) {
	d := NewDecoder(bytes.NewReader(data))
	opening, err := d.Opening()
	if err != nil {
		return nil, err
	}
	t := &Transmission{
		Handshake:      opening.Handshake,
		Acknowledge:    opening.Acknowledge,
		ClientEndpoint: opening.ClientEndpoint,
	}
	for {
		msg, err := d.Next()
		if errors.Is(err, io.EOF) {
			return t, nil
		}
		if err != nil {
			return nil, err
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
		b.Print(t.ClientEndpoint.ToString())
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
