package serz

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const existsFlag = "✅"
const notExistsFlag = "❌"

func extractName(name string) string {
	name = filepath.Base(name)
	blocks := strings.Split(name, ".")
	return blocks[0]
}

func extractPackage(name string) string {
	name = filepath.Dir(name)
	name = filepath.Base(name)
	return name
}

func TestYsoserial(t *testing.T) {
	walkAndTest("../testcases/ysoserial/*.ser", t, func(filename string, data []byte, ser *Serialization) {
		require.Truef(
			t,
			bytes.Equal(data, ser.ToBytes()),
			"original data is different from generation data in file %v",
			filename,
		)
	})
}

func TestJDK8u20(t *testing.T) {
	var filename = "../testcases/pwntester/JDK8u20.ser"
	data, err := ioutil.ReadFile(filename)
	require.Nil(t, err)

	ser, err := FromJDK8u20Bytes(data)
	require.Nilf(t, err, "an error is occurred in file %v", filename)
	require.Truef(t, bytes.Equal(data, ser.ToJDK8u20Bytes()), "original data is different from generation data in file %v", filename)
}

func TestMain(m *testing.M) {
	exitCode := m.Run()
	var (
		ysosers []string
		ptsers  []string
		files   []string
	)
	var err error

	ysosers, err = filepath.Glob("../testcases/ysoserial/*.ser")
	if err != nil {
		exitCode = exitCode | 1
		goto cleanup
	}

	ptsers, err = filepath.Glob("../testcases/pwntester/*.ser")
	if err != nil {
		exitCode = exitCode | 1
		goto cleanup
	}

	files = append(ysosers, ptsers...)
	fmt.Println("| Gadget | Package | Parsed | Rebuild | Parse Time |")
	fmt.Println("|--------|--------|--------|--------|--------|")
	for _, name := range files {
		var isJDK8u20 = strings.Contains(name, "JDK8u20")
		data, err := ioutil.ReadFile(name)
		if err != nil {
			exitCode = exitCode | 1
			goto cleanup
		}

		var parseFlag = notExistsFlag
		var rebuildFlag = notExistsFlag
		var serialization *Serialization
		var start = time.Now()

		if isJDK8u20 {
			serialization, err = FromJDK8u20Bytes(data)
		} else {
			serialization, err = FromBytes(data)
		}

		var duration = time.Since(start)

		if err == nil {
			parseFlag = existsFlag

			if isJDK8u20 && bytes.Equal(serialization.ToJDK8u20Bytes(), data) {
				rebuildFlag = existsFlag
			} else if !isJDK8u20 && bytes.Equal(serialization.ToBytes(), data) {
				rebuildFlag = existsFlag
			}
		}

		fmt.Printf("| %s | %s | %s | %s | %s |\n", extractName(name), extractPackage(name), parseFlag, rebuildFlag, duration)
	}

cleanup:
	os.Exit(exitCode)
}

func walkAndTest(pathGlob string, t *testing.T, callback func(filename string, data []byte, ser *Serialization)) {
	files, err := filepath.Glob(pathGlob)
	require.Nil(t, err)
	require.NotZero(t, len(files))

	for _, name := range files {
		data, err := ioutil.ReadFile(name)
		require.Nil(t, err)

		ser, err := FromBytes(data)
		require.Nilf(t, err, "an error is occurred in file %v", name)

		callback(name, data, ser)
	}
}
