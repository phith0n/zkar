package zkar

import (
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

/**
  implement io.Reader
*/
func (s *ObjectStream) Read(b []byte) (n int, err error) {
	if s.EOF() {
		return 0, io.EOF
	}
	n = copy(b, s.bs[s.current:])
	s.current += int64(n)
	return
}

// ReadN
/**
  读取N个字节的内容，如果n大于剩余的字符数，则返回空数组和错误，且指针恢复原状
*/
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

// PeekN
/**
  读取N个字节的内容，如果n大于剩余的字符数，则返回空数组和错误，且指针恢复原状
  与Read的区别是Peek不移动指针位置
*/
func (s *ObjectStream) PeekN(n int) (bs []byte, err error) {
	oldCurrent := s.current
	bs, err = s.ReadN(n)
	s.current = oldCurrent
	return
}

func (s *ObjectStream) Seek(pos int64) {
	s.current = pos
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
