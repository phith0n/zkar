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
// an io.ReadAll result, etc.). The buffered parser uses a sentinel-based
// arg loop that terminates on io.EOF or a next-frame flag — safe on any
// input that eventually reaches EOF, but would block forever on a live
// reader that keeps the connection open between frames. For live streams
// (net.Conn, pipes) use FromStream instead.
func FromBytes(data []byte) (*Transmission, error) {
	return parseTransmission(commons.NewStream(data), false)
}

// FromStream parses JRMP traffic from a live io.Reader (e.g. net.Conn)
// without io.ReadAll-ing the whole stream first. Each message's byte
// boundary is derived from protocol framing alone, so the parser won't
// block on an idle connection after finishing one message but before the
// next arrives.
//
// Scope (intentionally narrow):
//
//   - Handshake / Acknowledge / ClientEndpoint echo — bounded reads, fine.
//   - MsgCall — supported ONLY for java.rmi.registry.Registry (ObjID ==
//     REGISTRY_ID AND methodHash == RegistryInterfaceHash). Registry's
//     op-index yields exact arg count via registryArgCount; non-Registry
//     Calls return an error because we cannot know their arg count without
//     external method-signature info.
//   - MsgPing / MsgPingAck / MsgDgcAck — bounded, always supported.
//   - MsgReturnData — not supported. NormalReturn's 0-vs-1 payload count
//     needs call/response correlation we don't track; use FromBytes on a
//     buffered copy of the full conversation for return parsing.
//
// Loop exits on io.EOF (caller closed the reader) or the first error from
// a message reader.
func FromStream(r io.Reader) (*Transmission, error) {
	return parseTransmission(commons.NewStreamFromReader(r), true)
}

// parseTransmission is the single implementation behind both FromBytes and
// FromStream. The `streaming` flag propagates down into readCall / readReturn
// where it picks the arg-reading strategy.
func parseTransmission(stream *commons.Stream, streaming bool) (*Transmission, error) {
	t := &Transmission{}

	// Direction-agnostic opening: peek the first byte to decide what (if
	// anything) precedes the message loop.
	first, err := stream.PeekN(1)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return t, nil // empty input is a (degenerate) valid Transmission
		}
		return nil, fmt.Errorf("peek first byte: %w", err)
	}

	switch first[0] {
	case JRMI_MAGIC[0]: // 0x4A — client→server handshake
		h, herr := readHandshake(stream)
		if herr != nil {
			return nil, herr
		}
		t.Handshake = h

		// A conforming Stream-protocol client immediately follows the
		// 7-byte handshake with its own endpoint suggestion. Some
		// hand-crafted fixtures skip this; peek and decide.
		ep, eerr := maybeReadClientEndpoint(stream)
		if eerr != nil {
			return nil, fmt.Errorf("client endpoint echo: %w", eerr)
		}
		t.ClientEndpoint = ep

	case AckFlag: // 0x4E — server→client ProtocolAck
		a, aerr := readAcknowledge(stream)
		if aerr != nil {
			return nil, aerr
		}
		t.Acknowledge = a

		// No further server-side echo: Acknowledge already carries
		// the server's view of the client endpoint.
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
		msg, merr := readMessage(stream, streaming)
		if merr != nil {
			return nil, merr
		}
		t.Messages = append(t.Messages, msg)
	}
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
