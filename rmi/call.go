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
// Two arg-reading strategies share everything above the arg loop:
//
//   - streaming == false (buffered input like *.bin / bytes.Reader): sentinel
//     — read TCContents until PeekN yields a non-TC_* byte or io.EOF. The
//     sentinel relies on EOF or a next-frame flag (0x50..0x54) terminating
//     the loop; safe on any input that eventually EOFs, would block forever
//     on a live TCP reader.
//
//   - streaming == true (live io.Reader like net.Conn): exact count — we
//     require a Registry call (ObjID=REGISTRY_ID + hash=RegistryInterfaceHash),
//     look up the stub's arg count via registryArgCount(op), and read
//     precisely that many TCContents. No PeekN past the last arg means no
//     blocking on "maybe more bytes".
func readCall(outer *commons.Stream, streaming bool) (*CallMessage, error) {
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
	// sentinel to detect the end of the primitive region.
	blocks, primitive, err := readLeadingBlocks(inner, callPrimitiveLen)
	if err != nil {
		return nil, err
	}
	if len(primitive) > callPrimitiveLen {
		return nil, fmt.Errorf("call leading block has %d trailing primitive bytes after the 34-byte header; "+
			"only ObjID+op+hash is expected before writeObject args",
			len(primitive)-callPrimitiveLen)
	}

	objID, err := parseObjID(primitive[:objIDLen])
	if err != nil {
		return nil, err
	}
	op := int32(binary.BigEndian.Uint32(primitive[objIDLen : objIDLen+4]))
	hash := int64(binary.BigEndian.Uint64(primitive[objIDLen+4 : callPrimitiveLen]))

	args, err := readCallArgs(inner, streaming, objID, op, hash)
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

// readCallArgs returns the object-arg TCContents of a Call. Buffered mode
// sentinel-scans until non-TC_* / EOF; streaming mode requires a Registry
// call and reads exactly registryArgCount(op) contents.
func readCallArgs(inner *serz.ObjectStream, streaming bool, objID ObjID, op int32, hash int64) ([]*serz.TCContent, error) {
	if streaming {
		if !objID.IsRegistry() || hash != RegistryInterfaceHash {
			return nil, fmt.Errorf("streaming parser only supports Registry calls (ObjID=REGISTRY_ID + hash=RegistryInterfaceHash); "+
				"got ObjNum=%d hash=0x%X — buffer the full stream and use FromBytes for non-Registry remotes",
				objID.ObjNum, hash)
		}
		argCount, ok := registryArgCount(op)
		if !ok {
			return nil, fmt.Errorf("streaming parser only supports known Registry op-indices [0..4]; got op=%d", op)
		}
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

	// Buffered sentinel: stop on next-frame flag or EOF.
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
