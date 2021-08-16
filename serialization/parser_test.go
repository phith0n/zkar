package serialization

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"path/filepath"
	"testing"
)

func TestParser(t *testing.T) {
	files, err := filepath.Glob("testcases/ysoserial/*.ser")
	require.Nil(t, err)

	for _, name := range files {
		data, err := ioutil.ReadFile(name)
		require.Nil(t, err)

		ser, err := FromBytes(data)
		require.Nilf(t, err, "an error is occurred in file %v", name)
		require.Truef(t, bytes.Equal(data, ser.ToBytes()), "original serialization data is different from generation data in file %v", name)
	}
}
