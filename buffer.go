package javaserialize

import (
	"io"
)

type Stream struct {
	bs []byte
	current int64
}

func NewStream(bs []byte) *Stream {
	return &Stream{
		bs: bs,
		current: int64(0),
	}
}

/**
  implement io.Reader
 */
func (s *Stream) Read(b []byte) (n int, err error) {
	if s.current >= int64(len(s.bs)) {
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
func (s *Stream) ReadN(n int) (bs []byte, err error) {
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
func (s *Stream) PeekN(n int) (bs []byte, err error) {
	oldCurrent := s.current
	bs, err = s.ReadN(n)
	s.current = oldCurrent
	return
}
