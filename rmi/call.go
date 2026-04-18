package rmi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/phith0n/zkar/commons"
	"github.com/phith0n/zkar/serz"
)

// CallMessage parses a JRMP MsgCall (0x50): a complete Java serialization stream
// whose leading TC_BLOCKDATA carries the fixed 34-byte primitive payload
// (ObjID + int32 op + int64 methodHash) followed by the method arguments as
// ordinary TCContent entries.
type CallMessage struct {
	ObjID      ObjID
	Operation  int32
	MethodHash int64
	Raw        *serz.Serialization
	ObjectArgs []*serz.TCContent
	Decoded    *DecodedCall
}

func (*CallMessage) Op() byte { return MsgCall }

func (c *CallMessage) ToString() string {
	b := commons.NewPrinter()
	b.Printf("Call - %s", commons.Hexify(MsgCall))
	b.IncreaseIndent()
	// A compact summary — method + scalar arg values — at the top for quick
	// scanning. Complex args (Remote stubs etc.) are referenced by handler
	// here and fully rendered inline below in @Serialization, so no bytes
	// are printed twice.
	if c.Decoded != nil {
		b.Print(c.Decoded.ToString())
	}
	// Dissector-style embedded-stream walk: leading TC_BLOCKDATA is decomposed
	// into ObjID + op + hash in place, each arg TCContent carries a semantic
	// label on its header line. Every byte appears exactly once.
	printEmbeddedCall(b, c)
	return b.String()
}

// readCall consumes one MsgCall frame starting at the 0x50 flag byte.
//
// The arg reader picks one of two strategies based on what the header tells
// us about the Call:
//
//   - Exact count (Registry fast path): when ObjID == REGISTRY_ID,
//     hash == RegistryInterfaceHash, and op ∈ [0..4], we look up the stub's
//     arg count via registryArgCount(op) and read precisely that many
//     TCContents. No PeekN past the last arg, so the parser returns the
//     frame as soon as its own bytes arrive — even on a live TCP reader
//     where the peer is about to wait for a response before sending more.
//
//   - Sentinel (fallback): read TCContents until PeekN yields a non-TC_*
//     byte or io.EOF. Correct on any input, but the peek after the last arg
//     blocks on a live reader until the next frame's flag byte arrives, the
//     peer closes (io.EOF), or the reader's deadline fires. Callers that
//     need responsiveness on non-Registry Calls should set SetReadDeadline
//     on their net.Conn.
func readCall(outer *commons.Stream) (*CallMessage, error) {
	flagBs, err := outer.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("read Call flag on index %v: %w", outer.CurrentIndex(), err)
	}
	if flagBs[0] != MsgCall {
		return nil, fmt.Errorf("expected Call flag 0x50 on index %v, got %s",
			outer.CurrentIndex()-1, commons.Hexify(flagBs[0]))
	}

	// Share the outer commons.Stream: embedded serz reads advance the same
	// byte cursor, so after this function returns outer is exactly at the
	// byte right after the Call's final arg.
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

	// Read leading TC_BLOCKDATA(s) until we have ≥ 34 primitive bytes. Each
	// block's explicit length prefix keeps this bounded; we never rely on a
	// sentinel to detect the end of the primitive region. Non-Registry remotes
	// whose method signature includes primitive params (e.g. remote.foo(int))
	// legally flush the ObjID+op+hash header together with those primitive args
	// in a single block — we keep the full block in Raw and only slice the
	// header portion for the typed fields below.
	blocks, primitive, err := readLeadingBlocks(inner, callPrimitiveLen)
	if err != nil {
		return nil, err
	}

	objID, err := parseObjID(primitive[:objIDLen])
	if err != nil {
		return nil, err
	}
	op := int32(binary.BigEndian.Uint32(primitive[objIDLen : objIDLen+4]))
	hash := int64(binary.BigEndian.Uint64(primitive[objIDLen+4 : callPrimitiveLen]))

	args, err := readCallArgs(inner, objID, op, hash)
	if err != nil {
		return nil, err
	}

	contents := make([]*serz.TCContent, 0, len(blocks)+len(args))
	contents = append(contents, blocks...)
	contents = append(contents, args...)
	ser := &serz.Serialization{
		MagicNumber:   append([]byte{}, magic...),
		StreamVersion: append([]byte{}, version...),
		Contents:      contents,
	}
	call := &CallMessage{
		ObjID:      objID,
		Operation:  op,
		MethodHash: hash,
		Raw:        ser,
		ObjectArgs: args,
	}
	// Registry dispatch: the stub signs every call with the well-known ObjID
	// + interface hash, and encodes the method as the op-index. Guard on
	// both so a non-Registry remote whose hash happens to collide can't be
	// misdecoded. Decoder errors are non-fatal — Raw still holds the tree.
	if objID.IsRegistry() && hash == RegistryInterfaceHash {
		if decoder, ok := registryDecoders[op]; ok {
			if decoded, derr := decoder(args); derr == nil {
				call.Decoded = decoded
			}
		}
	}
	return call, nil
}

// readLeadingBlocks consumes TC_BLOCKDATA / TC_BLOCKDATALONG contents from
// `inner` until the concatenated payload reaches at least `want` bytes.
// Returns the blocks read and the concatenated payload.
func readLeadingBlocks(inner *serz.ObjectStream, want int) ([]*serz.TCContent, []byte, error) {
	var blocks []*serz.TCContent
	var primitive []byte
	for len(primitive) < want {
		peek, err := inner.PeekN(1)
		if err != nil {
			return nil, nil, fmt.Errorf("peek leading block: %w", err)
		}
		if peek[0] != serz.JAVA_TC_BLOCKDATA && peek[0] != serz.JAVA_TC_BLOCKDATALONG {
			return nil, nil, fmt.Errorf("expected TC_BLOCKDATA(LONG) for primitive header on index %v, got %s",
				inner.CurrentIndex(), commons.Hexify(peek[0]))
		}
		content, err := serz.ReadTCContent(inner)
		if err != nil {
			return nil, nil, fmt.Errorf("read leading block: %w", err)
		}
		blocks = append(blocks, content)
		primitive = append(primitive, content.BlockData.Data...)
	}
	return blocks, primitive, nil
}

// readCallArgs returns the object-arg TCContents of a Call.
//
// Fast path: a conforming Registry call (matching ObjID + interface hash +
// known op-index) has a well-defined arg count, so we read exactly that many
// and return — no peek past the last arg, no blocking on a live reader
// waiting for "maybe more bytes".
//
// Fallback: for any other Call we don't know the method signature, so we
// fall back to a sentinel scan (read TCContents until PeekN yields a byte
// outside the TC_* range or io.EOF). The sentinel's terminating peek blocks
// on a live reader until the next frame's flag byte arrives, the peer
// closes, or the reader's deadline fires.
func readCallArgs(inner *serz.ObjectStream, objID ObjID, op int32, hash int64) ([]*serz.TCContent, error) {
	if objID.IsRegistry() && hash == RegistryInterfaceHash {
		if argCount, ok := registryArgCount(op); ok {
			args := make([]*serz.TCContent, 0, argCount)
			for i := 0; i < argCount; i++ {
				content, err := serz.ReadTCContent(inner)
				if err != nil {
					return nil, fmt.Errorf("read Call arg %d: %w", i, err)
				}
				args = append(args, content)
			}
			return args, nil
		}
	}

	// Sentinel: stop on next-frame flag or EOF.
	var args []*serz.TCContent
	for {
		next, err := inner.PeekN(1)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("peek Call arg: %w", err)
		}
		if next[0] < serz.JAVA_TC_BASE || next[0] > serz.JAVA_TC_MAX {
			break
		}
		content, cerr := serz.ReadTCContent(inner)
		if cerr != nil {
			return nil, fmt.Errorf("read Call arg: %w", cerr)
		}
		args = append(args, content)
	}
	return args, nil
}
