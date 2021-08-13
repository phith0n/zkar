package javaserialize

import (
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

		os := NewObjectInputStream()
		err = os.Read(data)
		require.Nilf(t, err, "An error is occurred in file %v", name)
	}
}
