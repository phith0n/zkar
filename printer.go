package zkar

import (
	"fmt"
	"strings"
)

type printer struct {
	strings.Builder
	currentIndent int
}

func (p *printer) printf(msg string, args ...interface{}) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	p.print(msg)
}

func (p *printer) print(data string) {
	var indent = strings.Repeat(" ", p.currentIndent)
	var blocks = strings.Split(data, "\n")
	for _, block := range blocks {
		if block != "" {
			_, _ = p.WriteString(indent + block + "\n")
		}
	}
}

func (p *printer) increaseIndent() {
	p.currentIndent += 2
}

func (p *printer) decreaseIndent() {
	if p.currentIndent >= 2 {
		p.currentIndent -= 2
	}
}

func newPrinter() *printer {
	return &printer{
		currentIndent: 0,
	}
}
