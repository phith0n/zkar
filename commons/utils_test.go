package commons

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

func TestHexify(t *testing.T) {
	var b byte = 0x8b
	require.Equal(t, "0x8b", Hexify(b))
	require.Equal(t, "0x8b a3", Hexify([]byte{b, 0xa3}))
	require.Equal(t, "0x00 01 02 03 04", Hexify([]byte("\x00\x01\x02\x03\x04")))
	require.Equal(t, "0xff ff f7 49", Hexify(uint32(4294965065)))
	require.Equal(t, "0x01", Hexify(true))
	require.Equal(t, "0x68 65 6c 6c 6f", Hexify("hello"))
}
