package rmi

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/phith0n/zkar/commons"
	"github.com/phith0n/zkar/serz"
)

// CallMessage parses a JRMP MsgCall (0x50) addressed at the well-known
// java.rmi.registry.Registry stub. The on-wire layout is a complete Java
// serialization stream whose leading TC_BLOCKDATA carries a fixed 34-byte
// primitive payload (ObjID + int32 op + int64 methodHash) followed by the
// method arguments as ordinary TCContent entries.
//
// This parser only accepts Registry calls: ObjID == REGISTRY_ID,
// methodHash == RegistryInterfaceHash, op ∈ [0..4]. Non-Registry calls fail
// at parse time — see readCall for the exact error messages. The sole
// consequence worth remembering: Operation is always one of the five
// {Bind, List, Lookup, Rebind, Unbind}OpIndex constants.
//
// Decoded is always non-nil for a successfully parsed CallMessage. Its
// Args slice is the human-oriented view (scalar values inlined, stub
// subtrees referenced by handler). ObjectArgs and Raw expose the raw
// TCContent tree for callers that want to walk the embedded stream.
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
	// are printed twice. Decoded is populated for every successfully parsed
	// CallMessage, but a non-fatal decoder error (e.g. malformed string arg)
	// can still leave it nil — guard the call.
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
// The frame header (ObjID + op + methodHash) is checked against the known
// Registry dispatch triple: ObjID == REGISTRY_ID, methodHash ==
// RegistryInterfaceHash, op ∈ [0..4]. Any mismatch is an error — this
// parser only handles java.rmi.registry.Registry stubs. Once the dispatch
// is confirmed, registryArgCount(op) gives the exact arg count and
// readCallArgs reads precisely that many TCContents. No peek past the last
// arg, so the parser returns as soon as the frame's own bytes arrive —
// critical on a live TCP reader where the peer may send one Call and then
// wait for a response before sending anything else.
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

	// Read leading TC_BLOCKDATA(s) until we have ≥ 34 primitive bytes.
	// Registry stubs always emit exactly 34 (ObjID + op + hash, no primitive
	// params), but the loop is written to tolerate a writer that splits the
	// primitive write across multiple blocks — each block's explicit length
	// prefix keeps this bounded.
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

	// Registry dispatch gate. A non-Registry ObjID, a mismatched interface
	// hash, or an op outside the stub's method table are all parse errors —
	// this parser only handles java.rmi.registry.Registry traffic.
	if !objID.IsRegistry() {
		return nil, fmt.Errorf("not a Registry call: ObjID.ObjNum=%d (expected 0 for REGISTRY_ID); this parser only supports java.rmi.registry.Registry stubs",
			objID.ObjNum)
	}
	if hash != RegistryInterfaceHash {
		return nil, fmt.Errorf("not a Registry call: methodHash=0x%X (expected 0x%X = RegistryInterfaceHash); this parser only supports java.rmi.registry.Registry stubs",
			hash, RegistryInterfaceHash)
	}
	argCount, ok := registryArgCount(op)
	if !ok {
		return nil, fmt.Errorf("unknown Registry op-index %d; expected bind(0), list(1), lookup(2), rebind(3), or unbind(4)", op)
	}

	args, err := readCallArgs(inner, argCount)
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
	// Semantic decoding: registryDecoders has an entry for every op in
	// [0..4], so the lookup always succeeds. A decoder error (e.g. args
	// aren't well-formed strings) is non-fatal — leave Decoded nil and
	// let callers inspect Raw / ObjectArgs.
	if decoded, derr := registryDecoders[op](args); derr == nil {
		call.Decoded = decoded
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

// readCallArgs reads exactly argCount object-arg TCContents from the
// embedded serialization stream. The caller has already validated the
// Registry dispatch triple (ObjID + hash + op), so argCount is the known
// arity of the stub's op-indexed method.
//
// No peek past the last arg means readCall returns as soon as the frame's
// own bytes have been consumed — critical for live TCP readers where the
// peer has sent one Call and is now waiting for a response.
func readCallArgs(inner *serz.ObjectStream, argCount int) ([]*serz.TCContent, error) {
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
