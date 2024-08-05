package commons

import (
	"bytes"
	"io"
)

type Stream struct {
	reader io.Reader

	buf    []byte
	index  int
}

func (s *Stream) ReadN(n int) ([]byte, error) {
	if n > len(s.buf)-s.index {
		buf := make([]byte, n-(len(s.buf)-s.index))
		read, err := io.ReadFull(s.reader, buf)
		s.buf = append(s.buf, buf[0:read]...)
		if err != nil {
			return nil, err
		}
	}

	start := s.index
	s.index += n
	return s.buf[start:s.index], nil
}

func (s *Stream) CurrentIndex() int {
	return s.index
}

func (s *Stream) PeekN(n int) ([]byte, error) {
	current := s.index
	defer func() {
		s.index = current
	}()
	return s.ReadN(n)
}

func (s *Stream) Seek(index int) {
	s.index = index
}

func NewStreamFromReader(reader io.Reader) *Stream {
	return &Stream{
		reader: reader,
		buf:    make([]byte, 0),
		index:  0,
	}
}

func NewStreamFromReadSeeker(rs io.ReadSeeker) *Stream {
	return NewStreamFromReader(rs)
}

func NewStream(bs []byte) *Stream {
	return NewStreamFromReader(bytes.NewReader(bs))
}
