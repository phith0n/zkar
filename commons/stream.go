package commons

import (
	"errors"
	"io"
)

type Stream struct {
	bs         []byte
	current    int64
}

func NewStream(bs []byte) *Stream {
	return &Stream{
		bs:         bs,
		current:    int64(0),
	}
}


// Read implement io.Reader
func (s *Stream) Read(b []byte) (n int, err error) {
	if s.EOF() {
		return 0, io.EOF
	}
	n = copy(b, s.bs[s.current:])
	s.current += int64(n)
	return
}

// ReadN read n bytes into byte array bs, it returns the byte array and any error encountered.
// If read data size < n, an error will be returned with nil bs
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

// PeekN read n bytes into byte array bs, it returns the byte array and any error encountered.
// This method is similar as ReadN, but the stream pointer wouldn't move
func (s *Stream) PeekN(n int) (bs []byte, err error) {
	oldCurrent := s.current
	bs, err = s.ReadN(n)
	s.current = oldCurrent
	return
}

// Seek implement io.Seeker
func (s *Stream) Seek(offset int64, whence int) (int64, error) {
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

func (s *Stream) EOF() bool {
	return s.current >= int64(len(s.bs))
}

func (s *Stream) CurrentIndex() int64 {
	return s.current
}
