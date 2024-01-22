package commons

import (
	"bytes"
	"errors"
	"io"
)

type CommonStream interface {
	io.ReadSeeker
	ReadN(n int) (bs []byte, err error)
	PeekN(n int) (bs []byte, err error)
	EOF() bool
	CurrentIndex() int64
}

type Stream struct {
	io.ReadSeeker
	current int64
	err     error
}

func (s *Stream) Read(b []byte) (n int, err error) {
	if _, err = s.Seek(s.current, io.SeekStart); err != nil {
		s.err = err
		return
	}
	n, err = s.ReadSeeker.Read(b)
	if err != nil {
		s.err = err
		return
	}
	s.current += int64(n)
	return
}

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

func (s *Stream) PeekN(n int) (bs []byte, err error) {
	oldOffset := s.current
	bs, err = s.ReadN(n)
	s.current = oldOffset
	return
}

func (s *Stream) EOF() bool {
	return s.err != nil
}

func (s *Stream) CurrentIndex() int64 {
	return s.current
}

func (s *Stream) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = s.current + offset
	default:
		return 0, errors.New("bytes.Reader.Seek: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("bytes.Reader.Seek: negative position")
	}
	s.current = abs
	return s.ReadSeeker.Seek(abs, whence)
}

func NewStreamFromReadSeeker(rs io.ReadSeeker) *Stream {
	return &Stream{
		ReadSeeker: rs,
		current:    0,
	}
}

func NewStream(bs []byte) *Stream {
	return NewStreamFromReadSeeker(bytes.NewReader(bs))
}
