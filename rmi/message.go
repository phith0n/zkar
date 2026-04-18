package rmi

import (
	"fmt"

	"github.com/phith0n/zkar/commons"
)

// Message is implemented by every JRMP frame after the handshake phase.
type Message interface {
	Op() byte
	ToString() string
}

// readMessage peeks the next byte and dispatches to the matching reader.
// Works identically for buffered and streaming input — the per-reader arg
// strategies (exact-count-for-Registry vs sentinel) are chosen internally
// based on each frame's header, not on the input source.
func readMessage(outer *commons.Stream) (Message, error) {
	next, err := outer.PeekN(1)
	if err != nil {
		return nil, err
	}
	switch next[0] {
	case MsgCall:
		return readCall(outer)
	case MsgReturnData:
		return readReturn(outer)
	case MsgPing:
		return readPing(outer)
	case MsgPingAck:
		return readPingAck(outer)
	case MsgDgcAck:
		return readDgcAck(outer)
	default:
		return nil, fmt.Errorf("unknown JRMP message flag %s on index %v",
			commons.Hexify(next[0]), outer.CurrentIndex())
	}
}
