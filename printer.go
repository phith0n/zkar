package zkar

import (
	"fmt"
	"strings"
)

type Printer struct {
	strings.Builder
	currentIndent int
}

func (p *Printer) Printf(msg string, args ...interface{}) {
	var data = fmt.Sprintf(msg, args...)
	p.indent(data)
}

func (p *Printer) PrintfNoIndent(msg string, args ...interface{}) {
	var data = fmt.Sprintf(msg, args...)
	_, _ = p.WriteString(data)
}

func (p *Printer) IncreaseIndent() {
	p.currentIndent += 2
}

func (p *Printer) DecreaseIndent() {
	if p.currentIndent >= 2 {
		p.currentIndent -= 2
	}
}

func (p *Printer) indent(data string) {
	var indent = strings.Repeat(" ", p.currentIndent)
	var blocks = strings.Split(data, "\n")
	for _, block := range blocks {
		if block != "" {
			_, _ = p.WriteString(indent + block + "\n")
		}
	}
}

func NewPrinter() *Printer {
	return &Printer{
		currentIndent: 0,
	}
}
