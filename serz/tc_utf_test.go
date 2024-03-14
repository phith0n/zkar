package serz

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCC6WithOverlongEncoding show how to read an exist payload and modify it to a UTF-8 overlong encoding payload.
func TestCC6WithOverlongEncoding(t *testing.T) {
	// read original CommonsCollections6 payload
	data, err := os.ReadFile("../testcases/ysoserial/CommonsCollections6.ser")
	require.NoError(t, err)
	ser, err := FromBytes(data)
	require.NoError(t, err)

	// enable UTF-8 overlong encoding feature
	err = ser.Walk(func(obj Object) error {
		if u, ok := obj.(*TCUtf); ok {
			u.SetOverlongSize(OverlongEncodingTwoBytes)
		}

		return nil
	})
	require.NoError(t, err)

	// generate new payload
	data2 := ser.ToBytes()

	// read new payload
	_, err = FromBytes(data2)
	require.NoError(t, err)
}

func TestToOverlongEncoding(t *testing.T) {
	require.Equal(t, []byte("\xC0\xAE"), toOverlongEncoding([]byte("."), OverlongEncodingTwoBytes))
	require.Equal(t, []byte("\xE0\x80\xAE"), toOverlongEncoding([]byte("."), OverlongEncodingThreeBytes))
	require.Equal(t, []byte("\xc1\xaf\xc1\xb2\xc1\xa7\xc0\xae\xc1\xa5\xc1\xb8\xc1\xa1\xc1\xad\xc1\xb0\xc1"+
		"\xac\xc1\xa5\xc0\xae\xc1\x85\xc1\xb6\xc1\xa9\xc1\xac"),
		toOverlongEncoding([]byte("org.example.Evil"), OverlongEncodingTwoBytes))

	require.Equal(t, []byte("."), fromOverlongEncoding(toOverlongEncoding([]byte("."), OverlongEncodingTwoBytes)))
	require.Equal(t, []byte("."), fromOverlongEncoding(toOverlongEncoding([]byte("."), OverlongEncodingThreeBytes)))
	require.Equal(t, []byte("org.example.Evil"), fromOverlongEncoding(toOverlongEncoding([]byte("org.example.Evil"), OverlongEncodingTwoBytes)))
	require.Equal(t, []byte("org.example.Evil"), fromOverlongEncoding(toOverlongEncoding([]byte("org.example.Evil"), OverlongEncodingThreeBytes)))

	require.Equal(t, []byte{0xC0, 0xFF}, fromOverlongEncoding([]byte{0xC0, 0xFF}))
	require.Equal(t, []byte{0xE0, 0xAE, 0x38}, fromOverlongEncoding([]byte{0xE0, 0xAE, 0x38}))
	require.Equal(t, []byte("org.example.Evil"), fromOverlongEncoding([]byte("org.example.Evil")))
}
