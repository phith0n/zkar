package serz

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func extractName(name string) string {
	name = filepath.Base(name)
	blocks := strings.Split(name, ".")
	return blocks[0]
}

func TestParser(t *testing.T) {
	files, err := filepath.Glob("../testcases/ysoserial/*.ser")
	require.Nil(t, err)
	require.NotZero(t, len(files))

	fmt.Println("| Gadget | Package | Parsed | Rebuild | Parse Time |")
	fmt.Println("|--------|--------|--------|--------|--------|")
	for _, name := range files {
		data, err := ioutil.ReadFile(name)
		require.Nil(t, err)

		start := time.Now()
		ser, err := FromBytes(data)
		duration := time.Since(start)
		require.Nilf(t, err, "an error is occurred in file %v", name)
		require.Truef(t, bytes.Equal(data, ser.ToBytes()), "original serz data is different from generation data in file %v", name)
		fmt.Printf("| %s | %s | %s | %s | %s |\n", extractName(name), "Ysoserial", "✅", "✅", duration)
	}
}
