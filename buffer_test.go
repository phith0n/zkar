package javaserialize

import (
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

func TestStream_Read(t *testing.T) {
	var bs []byte
	var err error
	var n int
	s := NewStream([]byte("1111122222333334444455555"))
	bs = make([]byte, 5)
	n, err = s.Read(bs)
	require.Equal(t, 5, n)
	require.Nil(t, err)
	require.Equal(t, []byte("11111"), bs)
	bs = make([]byte, 22)
	n, err = s.Read(bs)
	require.Equal(t, 20, n)
	require.Nil(t, nil, err)
	require.Equal(t, []byte("22222333334444455555\x00\x00"), bs)
	bs = make([]byte, 5)
	n, err = s.Read(bs)
	require.Equal(t, 0, n)
	require.Equal(t, io.EOF, err)
	require.Equal(t, []byte("\x00\x00\x00\x00\x00"), bs)
}

func TestStream_ReadN(t *testing.T) {
	var bs []byte
	var err error
	s := NewStream([]byte("1111122222333334444455555"))
	bs, err = s.ReadN(5)
	require.Nil(t, err)
	require.Equal(t, []byte("11111"), bs)
	bs, err = s.ReadN(23)
	require.Equal(t, io.ErrUnexpectedEOF, err)
	require.Nil(t, bs)
	bs, err = s.ReadN(10)
	require.Nil(t, err)
	require.Equal(t, []byte("2222233333"), bs)
}

func TestStream_PeekN(t *testing.T) {
	var bs []byte
	var err error
	s := NewStream([]byte("1111122222333334444455555"))
	bs, err = s.PeekN(5)
	require.Nil(t, err)
	require.Equal(t, []byte("11111"), bs)
	bs, err = s.PeekN(25)
	require.Nil(t, err)
	require.Equal(t, []byte("1111122222333334444455555"), bs)
	bs, err = s.PeekN(30)
	require.Equal(t, io.ErrUnexpectedEOF, err)
	require.Nil(t, bs)
	_, _ = s.ReadN(10)
	bs, err = s.PeekN(5)
	require.Nil(t, err)
	require.Equal(t, []byte("33333"), bs)
	bs, err = s.PeekN(10)
	require.Nil(t, err)
	require.Equal(t, []byte("3333344444"), bs)
	bs, err = s.PeekN(20)
	require.Equal(t, io.ErrUnexpectedEOF, err)
	require.Nil(t, bs)
}
