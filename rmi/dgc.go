package rmi

import (
	"fmt"

	"github.com/phith0n/zkar/commons"
)

// PingMessage (0x52): client→server DGC heartbeat. No payload.
type PingMessage struct{}

func (*PingMessage) Op() byte         { return MsgPing }
func (*PingMessage) ToString() string { return fmt.Sprintf("Ping - %s", commons.Hexify(MsgPing)) }

// PingAckMessage (0x53): server→client reply to Ping. No payload.
type PingAckMessage struct{}

func (*PingAckMessage) Op() byte { return MsgPingAck }
func (*PingAckMessage) ToString() string {
	return fmt.Sprintf("PingAck - %s", commons.Hexify(MsgPingAck))
}

// DgcAckMessage (0x54): 14-byte raw UID acknowledging a DGC lease.
// Unlike Call/ReturnData, the UID is written as bare primitives without an
// enclosing ObjectOutputStream, so we read it directly off the connection stream.
type DgcAckMessage struct {
	UID UID
}

func (*DgcAckMessage) Op() byte { return MsgDgcAck }
func (d *DgcAckMessage) ToString() string {
	b := commons.NewPrinter()
	b.Printf("DgcAck - %s", commons.Hexify(MsgDgcAck))
	b.IncreaseIndent()
	b.Print(d.UID.ToString())
	return b.String()
}

func readPing(s *commons.Stream) (*PingMessage, error) {
	bs, err := s.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("read Ping flag failed on index %v: %w", s.CurrentIndex(), err)
	}
	if bs[0] != MsgPing {
		return nil, fmt.Errorf("expected Ping flag 0x52, got %s", commons.Hexify(bs[0]))
	}
	return &PingMessage{}, nil
}

func readPingAck(s *commons.Stream) (*PingAckMessage, error) {
	bs, err := s.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("read PingAck flag failed on index %v: %w", s.CurrentIndex(), err)
	}
	if bs[0] != MsgPingAck {
		return nil, fmt.Errorf("expected PingAck flag 0x53, got %s", commons.Hexify(bs[0]))
	}
	return &PingAckMessage{}, nil
}

func readDgcAck(s *commons.Stream) (*DgcAckMessage, error) {
	bs, err := s.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("read DgcAck flag failed on index %v: %w", s.CurrentIndex(), err)
	}
	if bs[0] != MsgDgcAck {
		return nil, fmt.Errorf("expected DgcAck flag 0x54, got %s", commons.Hexify(bs[0]))
	}

	uidBs, err := s.ReadN(uidLen)
	if err != nil {
		return nil, fmt.Errorf("read DgcAck UID failed on index %v: %w", s.CurrentIndex(), err)
	}
	uid, err := parseUID(uidBs)
	if err != nil {
		return nil, err
	}
	return &DgcAckMessage{UID: uid}, nil
}
