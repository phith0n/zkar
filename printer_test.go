package zkar

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPrinterIndent(t *testing.T) {
	var b = newPrinter()
	b.increaseIndent()
	b.printf("a: 1\nb: 2")
	require.Equal(t, "  a: 1\n  b: 2\n", b.String())
}

func TestPrinterNoNewline(t *testing.T) {
	var b = newPrinter()
	b.printf("no newline")
	require.Equal(t, "no newline\n", b.String())
}

func TestPrinterNewline(t *testing.T) {
	var b = newPrinter()
	b.printf("\n")
	require.Equal(t, "", b.String())
}

func TestPrinterNewlines(t *testing.T) {
	var b = newPrinter()
	b.printf("\n\n\n\n\n")
	require.Equal(t, "", b.String())
}

func TestPrinterIndentLines(t *testing.T) {
	var b = newPrinter()
	b.increaseIndent()
	b.printf("\n\n\n")
	require.Equal(t, "", b.String())
}
