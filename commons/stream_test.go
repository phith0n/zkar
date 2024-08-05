package commons

import (
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
