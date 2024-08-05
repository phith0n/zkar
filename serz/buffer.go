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
