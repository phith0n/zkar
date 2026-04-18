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
// Works identically for buffered and streaming input: Call frames read
// exactly registryArgCount(op) TCContents (no peek past the last arg, so
// no blocking between frames on a live reader); Return frames use a
// sentinel peek to detect the 0-or-1 payload count because direction-
// agnostic parsing can't correlate the Return to its originating Call.
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
