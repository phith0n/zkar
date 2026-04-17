package serz

import (
	"io"

	"github.com/phith0n/zkar/commons"
)

type ObjectStream struct {
	*commons.Stream
	handler    uint32
	references map[uint32]Object
}

func NewObjectStream(bs []byte) *ObjectStream {
	return &ObjectStream{
		Stream:     commons.NewStream(bs),
		handler:    JAVA_BASE_WRITE_HANDLE,
		references: make(map[uint32]Object),
	}
}

func NewObjectStreamFromReader(r io.Reader) *ObjectStream {
	return &ObjectStream{
		Stream:     commons.NewStreamFromReader(r),
		handler:    JAVA_BASE_WRITE_HANDLE,
		references: make(map[uint32]Object),
	}
}

// NewObjectStreamFromStream wraps an existing *commons.Stream so the embedded
// serialization parse shares byte-cursor state with its caller. This is the
// constructor the rmi streaming parser uses: an outer commons.Stream reads
// framing (handshake, message flags) from a live io.Reader, and each Call's
// embedded parse gets its own ObjectStream (fresh handler table + references)
// that sees the same buffered bytes instead of ending up out of sync with the
// underlying reader.
//
// The returned ObjectStream shares the caller's Stream pointer, so advancing
// one advances both.
func NewObjectStreamFromStream(s *commons.Stream) *ObjectStream {
	return &ObjectStream{
		Stream:     s,
		handler:    JAVA_BASE_WRITE_HANDLE,
		references: make(map[uint32]Object),
	}
}

func (s *ObjectStream) AddReference(obj Object) {
	switch obj := obj.(type) {
	case *TCObject:
		obj.Handler = s.handler
	case *TCClass:
		obj.Handler = s.handler
	case *TCClassDesc:
		obj.Handler = s.handler
	case *TCProxyClassDesc:
		obj.Handler = s.handler
	case *TCString:
		obj.Handler = s.handler
	case *TCArray:
		obj.Handler = s.handler
	case *TCEnum:
		obj.Handler = s.handler
	default:
		panic("reference is not allowed here")
	}

	s.references[s.handler] = obj
	s.handler++
}

func (s *ObjectStream) FindReferenceId(find Object) uint32 {
	for handler, obj := range s.references {
		if obj == find {
			return handler
		}
	}

	return 0
}

func (s *ObjectStream) GetReference(handler uint32) Object {
	return s.references[handler]
}
