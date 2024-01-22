package commons

import (
	"bytes"
	"io"
)

type Stream struct {
	io.ReadSeeker
}

func (s *Stream) ReadN(n int) (bs []byte, err error) {
	bs = make([]byte, n)
	_, err = io.ReadFull(s, bs)
	return
}

func (s *Stream) CurrentIndex() int64 {
	n, _ := s.Seek(0, io.SeekCurrent)
	return n
}

func (s *Stream) PeekN(n int) (bs []byte, err error) {
	bs, err = s.ReadN(n)
	if err != nil {
		return
	}
	_, err = s.Seek(int64(-n), io.SeekCurrent)
	if err != nil {
		return
	}
	return
}

func NewStreamFromReadSeeker(rs io.ReadSeeker) *Stream {
	return &Stream{
		ReadSeeker: rs,
	}
}

func NewStream(bs []byte) *Stream {
	return NewStreamFromReadSeeker(bytes.NewReader(bs))
}
