package serialization

import (
	"errors"
	"io"
)

type ObjectStream struct {
	bs         []byte
	current    int64
	handler    uint32
	references map[uint32]Object
}

func NewObjectStream(bs []byte) *ObjectStream {
	return &ObjectStream{
		bs:         bs,
		current:    int64(0),
		handler:    JAVA_BASE_WRITE_HANDLE,
		references: make(map[uint32]Object),
	}
}


// Read implement io.Reader
func (s *ObjectStream) Read(b []byte) (n int, err error) {
	if s.EOF() {
		return 0, io.EOF
	}
	n = copy(b, s.bs[s.current:])
	s.current += int64(n)
	return
}

// ReadN read n bytes into byte array bs, it returns the byte array and any error encountered.
// If read data size < n, an error will be returned with nil bs
func (s *ObjectStream) ReadN(n int) (bs []byte, err error) {
	oldCurrent := s.current
	bs = make([]byte, n)
	_, err = io.ReadFull(s, bs)
	if err != nil {
		s.current = oldCurrent
		bs = nil
	}

	return
}

// PeekN read n bytes into byte array bs, it returns the byte array and any error encountered.
// This method is similar as ReadN, but the stream pointer wouldn't move
func (s *ObjectStream) PeekN(n int) (bs []byte, err error) {
	oldCurrent := s.current
	bs, err = s.ReadN(n)
	s.current = oldCurrent
	return
}

// Seek implement io.Seeker
func (s *ObjectStream) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = s.current + offset
	case io.SeekEnd:
		abs = int64(len(s.bs)) + offset
	default:
		return 0, errors.New("bytes.Reader.Seek: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("bytes.Reader.Seek: negative position")
	}
	s.current = abs
	return abs, nil
}

func (s *ObjectStream) EOF() bool {
	return s.current >= int64(len(s.bs))
}

func (s *ObjectStream) CurrentIndex() int64 {
	return s.current
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
