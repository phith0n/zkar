package rmi

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/phith0n/zkar/commons"
	"github.com/phith0n/zkar/serz"
)

// ReturnMessage parses a JRMP MsgReturnData (0x51): an embedded serialization
// stream whose leading TC_BLOCKDATA carries a 15-byte primitive payload
// (returnType byte + 14-byte UID), optionally followed by one TCContent
// payload (the method's return value for normal returns, the thrown object
// for exceptional returns, or absent for void methods).
type ReturnMessage struct {
	ReturnType byte
	AckUID     UID
	Raw        *serz.Serialization
	Payload    *serz.TCContent
}

func (*ReturnMessage) Op() byte { return MsgReturnData }

func (r *ReturnMessage) ToString() string {
	b := commons.NewPrinter()
	b.Printf("ReturnData - %s", commons.Hexify(MsgReturnData))
	b.IncreaseIndent()
	// Dissector-style: the 15-byte primitive header (returnType + UID) is
	// decomposed in place inside the TC_BLOCKDATA, and any payload TCContent
	// is annotated with "(return value)" or "(thrown Throwable)".
	printEmbeddedReturn(b, r)
	if r.Payload == nil {
		b.Printf("@Note - void return, no payload TCContent after the primitive header")
	}
	return b.String()
}

// readReturn consumes one MsgReturnData frame. In streaming mode we refuse
// immediately: a NormalReturn's 0-vs-1 payload count depends on the
// originating Call's return type, and we don't track call/response state.
// Buffered mode uses a sentinel payload read (0 or 1 TCContent) — the sentinel
// works there because the input eventually EOFs.
func readReturn(outer *commons.Stream, streaming bool) (*ReturnMessage, error) {
	if streaming {
		return nil, fmt.Errorf("streaming parser does not support ReturnData (0x51) on index %v: "+
			"void-vs-value payload requires call/response correlation; buffer the stream and use FromBytes instead",
			outer.CurrentIndex())
	}

	flagBs, err := outer.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("read ReturnData flag on index %v: %w", outer.CurrentIndex(), err)
	}
	if flagBs[0] != MsgReturnData {
		return nil, fmt.Errorf("expected ReturnData flag 0x51 on index %v, got %s",
			outer.CurrentIndex()-1, commons.Hexify(flagBs[0]))
	}

	inner := serz.NewObjectStreamFromStream(outer)

	magic, err := inner.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read embedded serialization magic: %w", err)
	}
	if !bytes.Equal(magic, serz.JAVA_STREAM_MAGIC) {
		return nil, fmt.Errorf("invalid embedded serialization magic %s", commons.Hexify(magic))
	}
	version, err := inner.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read embedded serialization version: %w", err)
	}

	// Methods returning a primitive (int / long / boolean / …) legally flush
	// the returnType+UID header together with the raw return value in the same
	// TC_BLOCKDATA — the full block stays in Raw, we only slice the 15-byte
	// header here.
	blocks, primitive, err := readLeadingBlocks(inner, returnPrimitiveLen)
	if err != nil {
		return nil, err
	}

	uid, err := parseUID(primitive[1:returnPrimitiveLen])
	if err != nil {
		return nil, err
	}

	// Buffered-mode payload: 0 or 1 TCContent via sentinel.
	var payload *serz.TCContent
	extras := 0
	for {
		next, perr := inner.PeekN(1)
		if perr != nil {
			if errors.Is(perr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("peek ReturnData payload: %w", perr)
		}
		if next[0] < serz.JAVA_TC_BASE || next[0] > serz.JAVA_TC_MAX {
			break
		}
		content, cerr := serz.ReadTCContent(inner)
		if cerr != nil {
			return nil, fmt.Errorf("read ReturnData payload: %w", cerr)
		}
		if payload == nil {
			payload = content
		} else {
			extras++
		}
	}
	if extras > 0 {
		return nil, fmt.Errorf("ReturnData has %d content(s) after the primitive header; expected 0 (void) or 1 (value/throwable)",
			extras+1)
	}

	contents := make([]*serz.TCContent, 0, len(blocks)+1)
	contents = append(contents, blocks...)
	if payload != nil {
		contents = append(contents, payload)
	}
	return &ReturnMessage{
		ReturnType: primitive[0],
		AckUID:     uid,
		Raw: &serz.Serialization{
			MagicNumber:   append([]byte{}, magic...),
			StreamVersion: append([]byte{}, version...),
			Contents:      contents,
		},
		Payload: payload,
	}, nil
}
