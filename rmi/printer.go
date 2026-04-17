package rmi

import (
	"fmt"
	"strings"

	"github.com/phith0n/zkar/commons"
	"github.com/phith0n/zkar/serz"
)

// printEmbeddedCall and printEmbeddedReturn render the serialization stream
// wrapped by Call/ReturnData messages with wireshark-dissector-style inline
// annotations: the leading TC_BLOCKDATA is decomposed in place into its
// logical fields (ObjID + op + hash for Call; returnType + UID for Return),
// and subsequent TCContent args are prefixed with the method parameter name
// when we've decoded it. Every byte is printed exactly once.

// printEmbeddedCall writes c.Raw to b as @Magic / @Version / @Contents with
// the Call's primitive header decomposed and arg contents annotated.
func printEmbeddedCall(b *commons.Printer, c *CallMessage) {
	if c.Raw == nil {
		return
	}
	b.Printf("@Serialization")
	b.IncreaseIndent()
	defer b.DecreaseIndent()

	b.Printf("@Magic - %s", commons.Hexify(c.Raw.MagicNumber))
	b.Printf("@Version - %s", commons.Hexify(c.Raw.StreamVersion))
	b.Printf("@Contents")
	b.IncreaseIndent()
	defer b.DecreaseIndent()

	leading, rest := splitLeadingBlocks(c.Raw.Contents)
	if len(leading) > 0 {
		printPrimitiveBlocks(b, leading, callPrimitiveLen, func(data []byte) {
			writeCallPrimitiveFields(b, data, c)
		}, "Call primitives: ObjID + op + methodHash")
	}

	for i, ct := range rest {
		label := ""
		if c.Decoded != nil && i < len(c.Decoded.Args) {
			label = fmt.Sprintf("  (%s arg %d: %q)", c.Decoded.Method, i, c.Decoded.Args[i].Name)
		}
		printTCContentWithHeaderSuffix(b, ct, label)
	}
}

func printEmbeddedReturn(b *commons.Printer, r *ReturnMessage) {
	if r.Raw == nil {
		return
	}
	b.Printf("@Serialization")
	b.IncreaseIndent()
	defer b.DecreaseIndent()

	b.Printf("@Magic - %s", commons.Hexify(r.Raw.MagicNumber))
	b.Printf("@Version - %s", commons.Hexify(r.Raw.StreamVersion))
	b.Printf("@Contents")
	b.IncreaseIndent()
	defer b.DecreaseIndent()

	leading, rest := splitLeadingBlocks(r.Raw.Contents)
	if len(leading) > 0 {
		printPrimitiveBlocks(b, leading, returnPrimitiveLen, func(data []byte) {
			writeReturnPrimitiveFields(b, data, r)
		}, "ReturnData primitives: returnType + UID")
	}

	for _, ct := range rest {
		label := ""
		switch r.ReturnType {
		case NormalReturn:
			label = "  (return value)"
		case ExceptionalReturn:
			label = "  (thrown Throwable)"
		}
		printTCContentWithHeaderSuffix(b, ct, label)
	}
}

// splitLeadingBlocks returns the prefix of contents that are TC_BLOCKDATA(LONG)
// and the remainder. The prefix carries the fixed-size primitive payload of
// Call/Return, the remainder holds writeObject args.
func splitLeadingBlocks(contents []*serz.TCContent) ([]*serz.TCContent, []*serz.TCContent) {
	n := 0
	for _, ct := range contents {
		if ct.Flag != serz.JAVA_TC_BLOCKDATA && ct.Flag != serz.JAVA_TC_BLOCKDATALONG {
			break
		}
		n++
	}
	return contents[:n], contents[n:]
}

// printPrimitiveBlocks prints the leading BlockData(s) with their flag + length
// headers (matching serz's TC_BLOCKDATA rendering) and replaces the raw
// @Blockdata hex blob with the fields produced by `writeFields`, which sees
// the concatenated primitive payload.
//
// Common case is a single TC_BLOCKDATA carrying exactly `want` bytes; the
// multi-block fallback concatenates and prints each block's envelope
// separately so the wire structure remains observable.
func printPrimitiveBlocks(
	b *commons.Printer,
	blocks []*serz.TCContent,
	want int,
	writeFields func(data []byte),
	label string,
) {
	if len(blocks) == 1 {
		blk := blocks[0]
		if blk.Flag == serz.JAVA_TC_BLOCKDATA {
			b.Printf("TC_BLOCKDATA - %s  (%s)", commons.Hexify(serz.JAVA_TC_BLOCKDATA), label)
			b.IncreaseIndent()
			b.Printf("@Length - %d - %s", len(blk.BlockData.Data), commons.Hexify(uint8(len(blk.BlockData.Data))))
		} else {
			b.Printf("TC_BLOCKDATALONG - %s  (%s)", commons.Hexify(serz.JAVA_TC_BLOCKDATALONG), label)
			b.IncreaseIndent()
			b.Printf("@Length - %d - %s", len(blk.BlockData.Data), commons.Hexify(uint32(len(blk.BlockData.Data))))
		}
		writeFields(blk.BlockData.Data)
		if len(blk.BlockData.Data) > want {
			b.Printf("@PrimitiveTail - %s", commons.Hexify(blk.BlockData.Data[want:]))
		}
		b.DecreaseIndent()
		return
	}

	// Multi-block fallback: defensive path for a JDK that ever splits the
	// primitive header across blocks. Print each block's envelope, then the
	// concatenated decomposition alongside for clarity.
	var all []byte
	for _, blk := range blocks {
		b.Print(blk.ToString())
		all = append(all, blk.BlockData.Data...)
	}
	b.Printf("(leading blocks concatenated: %s)", label)
	b.IncreaseIndent()
	writeFields(all)
	if len(all) > want {
		b.Printf("@PrimitiveTail - %s", commons.Hexify(all[want:]))
	}
	b.DecreaseIndent()
}

func writeCallPrimitiveFields(b *commons.Printer, data []byte, c *CallMessage) {
	if len(data) < callPrimitiveLen {
		b.Printf("@PrimitivesTruncated - have %d bytes, need %d", len(data), callPrimitiveLen)
		return
	}
	// ObjID (22 bytes) = ObjNum(8) + UID(14)
	b.Printf("ObjID")
	b.IncreaseIndent()
	suffix := ""
	if c.ObjID.IsRegistry() {
		suffix = " (REGISTRY_ID)"
	}
	b.Printf("@ObjNum - %d%s - %s", c.ObjID.ObjNum, suffix, commons.Hexify(data[0:8]))
	b.Printf("UID")
	b.IncreaseIndent()
	b.Printf("@Unique - %d - %s", c.ObjID.UID.Unique, commons.Hexify(data[8:12]))
	b.Printf("@Time - %d - %s", c.ObjID.UID.Time, commons.Hexify(data[12:20]))
	b.Printf("@Count - %d - %s", c.ObjID.UID.Count, commons.Hexify(data[20:22]))
	b.DecreaseIndent()
	b.DecreaseIndent()
	// op (4 bytes) + hash (8 bytes)
	b.Printf("@Operation - %d - %s", c.Operation, commons.Hexify(data[22:26]))
	b.Printf("@MethodHash - %d - %s", c.MethodHash, commons.Hexify(data[26:34]))
}

func writeReturnPrimitiveFields(b *commons.Printer, data []byte, r *ReturnMessage) {
	if len(data) < returnPrimitiveLen {
		b.Printf("@PrimitivesTruncated - have %d bytes, need %d", len(data), returnPrimitiveLen)
		return
	}
	rt := data[0]
	var rtLabel string
	switch rt {
	case NormalReturn:
		rtLabel = "NormalReturn"
	case ExceptionalReturn:
		rtLabel = "ExceptionalReturn"
	default:
		rtLabel = "unknown"
	}
	b.Printf("@ReturnType - %s (%s)", commons.Hexify(rt), rtLabel)
	b.Printf("UID")
	b.IncreaseIndent()
	b.Printf("@Unique - %d - %s", r.AckUID.Unique, commons.Hexify(data[1:5]))
	b.Printf("@Time - %d - %s", r.AckUID.Time, commons.Hexify(data[5:13]))
	b.Printf("@Count - %d - %s", r.AckUID.Count, commons.Hexify(data[13:15]))
	b.DecreaseIndent()
}

// printTCContentWithHeaderSuffix delegates rendering to serz's TCContent.ToString
// but appends `suffix` to the header line (first line) so the reader sees
// the semantic label right next to the TC_* flag.
func printTCContentWithHeaderSuffix(b *commons.Printer, ct *serz.TCContent, suffix string) {
	raw := ct.ToString()
	if suffix == "" {
		b.Print(raw)
		return
	}
	if idx := strings.Index(raw, "\n"); idx >= 0 {
		b.Print(raw[:idx] + suffix + raw[idx:])
	} else {
		b.Print(raw + suffix)
	}
}

// summarizeTCContentRef is used by DecodedCall.ToString for args whose value
// is a raw TCContent (Remote stubs, TCNull, references). It produces a short
// pointer into @Contents instead of re-dumping the subtree.
func summarizeTCContentRef(c *serz.TCContent) string {
	switch c.Flag {
	case serz.JAVA_TC_OBJECT:
		if c.Object != nil {
			return fmt.Sprintf("TC_OBJECT handler %d — see @Contents", c.Object.Handler)
		}
		return "TC_OBJECT — see @Contents"
	case serz.JAVA_TC_NULL:
		return "TC_NULL"
	case serz.JAVA_TC_REFERENCE:
		if c.Reference != nil {
			return fmt.Sprintf("TC_REFERENCE to handler %d — see @Contents", c.Reference.Handler)
		}
		return "TC_REFERENCE — see @Contents"
	default:
		return fmt.Sprintf("TC_* flag %s — see @Contents", commons.Hexify(c.Flag))
	}
}
