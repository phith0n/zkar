package commons

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStream_ReadN(t *testing.T) {
	var bs []byte
	var err error
	s := NewStream([]byte("1111122222333334444455555"))
	bs, err = s.ReadN(5)
	require.Nil(t, err)
	require.Equal(t, []byte("11111"), bs)
	_, err = s.ReadN(23)
	require.Equal(t, io.ErrUnexpectedEOF, err)
}

func TestStream_PeekN(t *testing.T) {
	var bs []byte
	var err error
	s := NewStream([]byte("1111122222333334444455555"))
	bs, err = s.PeekN(5)
	require.Nil(t, err)
	require.Equal(t, []byte("11111"), bs)
	_, err = s.PeekN(25)
	require.Nil(t, err)
}

func TestStream_CurrentIndex(t *testing.T) {
	var bs []byte
	var err error
	s := NewStream([]byte("1111122222333334444455555"))
	bs, err = s.PeekN(5)
	require.Nil(t, err)
	require.Equal(t, []byte("11111"), bs)
	require.Equal(t, 0, s.CurrentIndex())

	bs, err = s.ReadN(5)
	require.Nil(t, err)
	require.Equal(t, []byte("11111"), bs)
	require.Equal(t, 5, s.CurrentIndex())
}

func TestStreamReader(t *testing.T) {
	var s *Stream
	var data []byte
	var err error

	s = NewStreamFromReader(bytes.NewReader([]byte("abbcccddddeeeee")))
	data, err = s.ReadN(1)
	require.NoError(t, err)
	require.Equal(t, []byte("a"), data)
	data, err = s.ReadN(5)
	require.NoError(t, err)
	require.Equal(t, []byte("bbccc"), data)
	data, err = s.PeekN(3)
	require.NoError(t, err)
	require.Equal(t, []byte("ddd"), data)
	data, err = s.PeekN(2)
	require.NoError(t, err)
	require.Equal(t, []byte("dd"), data)
	data, err = s.PeekN(5)
	require.NoError(t, err)
	require.Equal(t, []byte("dddde"), data)
	data, err = s.ReadN(4)
	require.NoError(t, err)
	require.Equal(t, []byte("dddd"), data)
	data, err = s.ReadN(1)
	require.NoError(t, err)
	require.Equal(t, []byte("e"), data)
	data, err = s.ReadN(3)
	require.NoError(t, err)
	require.Equal(t, []byte("eee"), data)
	_, err = s.PeekN(4)
	require.Error(t, err)
	data, err = s.PeekN(1)
	require.NoError(t, err)
	require.Equal(t, []byte("e"), data)
	_, err = s.ReadN(2)
	require.Error(t, err)
	data, err = s.ReadN(1)
	require.NoError(t, err)
	require.Equal(t, []byte("e"), data)
	_, err = s.ReadN(1)
	require.Error(t, err)
}

func TestEmptyStream(t *testing.T) {
	var s *Stream
	var data []byte
	var err error

	s = NewStreamFromReader(bytes.NewReader([]byte{}))
	data, err = s.ReadN(2)
	require.Error(t, err)
	require.Nil(t, data)

	_, err = s.PeekN(1)
	require.Error(t, err)

	s = NewStreamFromReader(bytes.NewReader(nil))
	_, err = s.ReadN(1)
	require.Error(t, err)
}

func TestStreamBuf(t *testing.T) {
	var s *Stream
	var data []byte
	var err error

	s = NewStreamFromReader(bytes.NewReader([]byte("abbcccddddeeeee")))
	_, err = s.PeekN(20)
	require.Error(t, err)

	data, err = s.PeekN(3)
	require.NoError(t, err)
	require.Equal(t, []byte("abb"), data)

	data, err = s.ReadN(5)
	require.NoError(t, err)
	require.Equal(t, []byte("abbcc"), data)

	data, err = s.PeekN(10)
	require.NoError(t, err)
	require.Equal(t, []byte("cddddeeeee"), data)
}
