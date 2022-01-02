package class

import (
	"github.com/phith0n/litter"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"testing"
)

func TestParseClass(t *testing.T) {
	t.SkipNow()

	data, err := ioutil.ReadFile("../testcases/classfile/TrainPrint.class")
	require.Nil(t, err)

	classFile, err := ParseClass(data)
	require.Nil(t, err)

	litter.Dump(classFile)
}
