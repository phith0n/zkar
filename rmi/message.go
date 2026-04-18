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
// `streaming` picks the arg-reading strategy for Call (exact-count-for-
// Registry vs sentinel) and the gating for Return (refused in streaming
// mode because payload count needs call/response correlation we don't keep).
func readMessage(outer *commons.Stream, streaming bool) (Message, error) {
	next, err := outer.PeekN(1)
	if err != nil {
		return nil, err
	}
	switch next[0] {
	case MsgCall:
		return readCall(outer, streaming)
	case MsgReturnData:
		return readReturn(outer, streaming)
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
