package javaserialize

import (
	orderedmap "github.com/wk8/go-ordered-map"
	"io"
)

type ObjectStream struct {
	bs []byte
	current int64
	BaseHandler uint32
	bag *orderedmap.OrderedMap
}

func NewObjectStream(bs []byte) *ObjectStream {
	return &ObjectStream{
		bs: bs,
		current: int64(0),
		BaseHandler: JAVA_BASE_WRITE_HANDLE,
		bag: orderedmap.New(),
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

func (s *ObjectStream) EOF() bool {
	return s.current >= int64(len(s.bs))
}

func (s *ObjectStream) CurrentIndex() int64 {
	return s.current
}

func (s *ObjectStream) AddBag(bag *orderedmap.OrderedMap) {
	for pair := bag.Oldest(); pair != nil; pair = pair.Next() {
		s.bag.Set(pair.Key, pair.Value)
	}
}

func (s *ObjectStream) GetBag() *orderedmap.OrderedMap {
	return s.bag
}
