package serz

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestObjectStream(t *testing.T) {
	var s = NewObjectStream([]byte("aaaabbbbccccdddd"))
	var tcs = NewTCString("this is a string", 0)
	s.AddReference(tcs)
	require.Equal(t, tcs, s.GetReference(tcs.Handler))
	require.Equal(t, tcs.Handler, s.FindReferenceId(tcs))
}
