package rmi

import (
	"fmt"

	"github.com/phith0n/zkar/commons"
	"github.com/phith0n/zkar/serz"
)

// DecodedCall is a semantic interpretation of a CallMessage whose method hash
// matches a known Registry stub method.
type DecodedCall struct {
	Method string
	Args   []DecodedArg
}

// DecodedArg is one argument of a decoded call. Value is a Go-native string
// for String arguments, or the raw *serz.TCContent for object arguments we
// don't pretty-print (e.g. the Remote stub in bind/rebind).
type DecodedArg struct {
	Name  string
	Type  string
	Value any
}

// ToString renders a compact summary: method name + scalar-arg values. Raw
// TCContent args (Remote stubs, null-like, references) are only referenced
// by handler so the reader can locate them in the embedded @Serialization
// tree without seeing the bytes twice.
func (d *DecodedCall) ToString() string {
	b := commons.NewPrinter()
	b.Printf("@Decoded")
	b.IncreaseIndent()
	b.Printf("@Method - %s", d.Method)
	if len(d.Args) == 0 {
		b.Printf("@Args - (none)")
		return b.String()
	}
	b.Printf("@Args")
	b.IncreaseIndent()
	for i, arg := range d.Args {
		switch v := arg.Value.(type) {
		case string:
			b.Printf("[%d] %s (%s) = %q", i, arg.Name, arg.Type, v)
		case *serz.TCContent:
			b.Printf("[%d] %s (%s) — %s", i, arg.Name, arg.Type, summarizeTCContentRef(v))
		default:
			b.Printf("[%d] %s (%s) = %v", i, arg.Name, arg.Type, v)
		}
	}
	return b.String()
}

// RegistryDecoder turns the object-argument slice of a Registry CallMessage
// into a DecodedCall. It is only invoked when the CallMessage's ObjID is
// REGISTRY_ID and the call's methodHash equals RegistryInterfaceHash; the
// map key is the op-index carried in CallMessage.Operation.
type RegistryDecoder func(objArgs []*serz.TCContent) (*DecodedCall, error)

var registryDecoders = map[int32]RegistryDecoder{
	BindOpIndex:   decodeBind,
	ListOpIndex:   decodeList,
	LookupOpIndex: decodeLookup,
	RebindOpIndex: decodeRebind,
	UnbindOpIndex: decodeUnbind,
}

// registryArgCount returns how many writeObject args immediately follow the
// primitive header for the given Registry op-index. Used by the streaming
// parser: once we've identified a Registry Call, we know exactly how many
// more TCContents to read — no sentinel peek, no blocking on a live TCP
// reader waiting for "maybe more bytes".
//
// Counts come from sun.rmi.registry.RegistryImpl_Stub:
//   bind(String, Remote)   → 2
//   list()                 → 0
//   lookup(String)         → 1
//   rebind(String, Remote) → 2
//   unbind(String)         → 1
func registryArgCount(op int32) (int, bool) {
	switch op {
	case BindOpIndex, RebindOpIndex:
		return 2, true
	case LookupOpIndex, UnbindOpIndex:
		return 1, true
	case ListOpIndex:
		return 0, true
	default:
		return 0, false
	}
}

func decodeLookup(args []*serz.TCContent) (*DecodedCall, error) {
	return decodeSingleStringArg("Registry.lookup", args)
}

func decodeUnbind(args []*serz.TCContent) (*DecodedCall, error) {
	return decodeSingleStringArg("Registry.unbind", args)
}

func decodeSingleStringArg(method string, args []*serz.TCContent) (*DecodedCall, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("decoding %s: expected 1 arg, got %d", method, len(args))
	}
	name, err := extractString(args[0])
	if err != nil {
		return nil, fmt.Errorf("decoding %s arg 0 (name): %w", method, err)
	}
	return &DecodedCall{
		Method: method,
		Args:   []DecodedArg{{Name: "name", Type: "String", Value: name}},
	}, nil
}

func decodeBind(args []*serz.TCContent) (*DecodedCall, error) {
	return decodeNameAndRemote("Registry.bind", args)
}

func decodeRebind(args []*serz.TCContent) (*DecodedCall, error) {
	return decodeNameAndRemote("Registry.rebind", args)
}

func decodeList(args []*serz.TCContent) (*DecodedCall, error) {
	if len(args) != 0 {
		return nil, fmt.Errorf("decoding Registry.list: expected 0 args, got %d", len(args))
	}
	return &DecodedCall{Method: "Registry.list"}, nil
}

func decodeNameAndRemote(method string, args []*serz.TCContent) (*DecodedCall, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("decoding %s: expected 2 args, got %d", method, len(args))
	}
	name, err := extractString(args[0])
	if err != nil {
		return nil, fmt.Errorf("decoding %s arg 0 (name): %w", method, err)
	}
	return &DecodedCall{
		Method: method,
		Args: []DecodedArg{
			{Name: "name", Type: "String", Value: name},
			{Name: "obj", Type: "Remote", Value: args[1]},
		},
	}, nil
}

// extractString pulls a Go string out of a TCContent that is expected to be
// a String-kind argument. It handles direct TC_STRING / TC_LONGSTRING and a
// TC_REFERENCE pointing at a previously-written string.
func extractString(c *serz.TCContent) (string, error) {
	switch c.Flag {
	case serz.JAVA_TC_STRING, serz.JAVA_TC_LONGSTRING:
		if c.String == nil || c.String.Utf == nil {
			return "", fmt.Errorf("TC_STRING content has nil Utf")
		}
		return c.String.Utf.Data, nil
	case serz.JAVA_TC_REFERENCE:
		if c.Reference == nil {
			return "", fmt.Errorf("TC_REFERENCE content has nil Reference")
		}
		if c.Reference.Flag != serz.JAVA_TC_STRING {
			return "", fmt.Errorf("TC_REFERENCE points at flag %s, not TC_STRING", commons.Hexify(c.Reference.Flag))
		}
		if c.Reference.String == nil || c.Reference.String.Utf == nil {
			return "", fmt.Errorf("referenced TC_STRING has nil Utf")
		}
		return c.Reference.String.Utf.Data, nil
	default:
		return "", fmt.Errorf("expected TC_STRING/TC_LONGSTRING/TC_REFERENCE, got %s", commons.Hexify(c.Flag))
	}
}
