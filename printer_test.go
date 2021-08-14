package javaserialize

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPrinter(t *testing.T) {
	var b = NewPrinter()
	b.IncreaseIndent()
	b.Printf("a: 1\nb: 2")
	require.Equal(t, "  a: 1\n  b: 2", b.String())
}
