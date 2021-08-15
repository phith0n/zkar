package zkar

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPrinterIndent(t *testing.T) {
	var b = NewPrinter()
	b.IncreaseIndent()
	b.Printf("a: 1\nb: 2")
	require.Equal(t, "  a: 1\n  b: 2\n", b.String())
}

func TestPrinterNoNewline(t *testing.T) {
	var b = NewPrinter()
	b.Printf("no newline")
	require.Equal(t, "no newline\n", b.String())
}

func TestPrinterNewline(t *testing.T) {
	var b = NewPrinter()
	b.Printf("\n")
	require.Equal(t, "", b.String())
}

func TestPrinterNewlines(t *testing.T) {
	var b = NewPrinter()
	b.Printf("\n\n\n\n\n")
	require.Equal(t, "", b.String())
}

func TestPrinterIndentLines(t *testing.T) {
	var b = NewPrinter()
	b.IncreaseIndent()
	b.Printf("\n\n\n")
	require.Equal(t, "", b.String())
}
