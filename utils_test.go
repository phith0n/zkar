package zkar

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNumberToBytes(t *testing.T) {
	var i1 int = -2324
	require.Equal(t, []byte("\xff\xff\xff\xff\xff\xff\xf6\xec"), NumberToBytes(i1))
	var i2 int16 = -2324
	require.Equal(t, []byte("\xf6\xec"), NumberToBytes(i2))
	var i3 int32 = -1234
	require.Equal(t, []byte("\xff\xff\xfb\x2e"), NumberToBytes(i3))
	var i4 int64 = 630391575257
	require.Equal(t, []byte("\x00\x00\x00\x92\xc6\x44\x12\xd9"), NumberToBytes(i4))
	var i5 uint64 = 630391575257
	require.Equal(t, NumberToBytes(i4), NumberToBytes(i5))
	var i6 uint32 = 4294965065
	require.Equal(t, []byte("\xff\xff\xf7\x49"), NumberToBytes(i6))
	var i7 int64 = -630391575257
	require.Equal(t, []byte("\xff\xff\xff\x6d\x39\xbb\xed\x27"), NumberToBytes(i7))
}
