package commons

import (
	"fmt"
	"strings"
)

type Printer struct {
	strings.Builder
	currentIndent int
}

func (p *Printer) Printf(msg string, args ...interface{}) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	p.Print(msg)
}

func (p *Printer) Print(data string) {
	var indent = strings.Repeat(" ", p.currentIndent)
	var blocks = strings.Split(data, "\n")
	for _, block := range blocks {
		if block != "" {
			_, _ = p.WriteString(indent + block + "\n")
		}
	}
}

func (p *Printer) IncreaseIndent() {
	p.currentIndent += 2
}

func (p *Printer) DecreaseIndent() {
	if p.currentIndent >= 2 {
		p.currentIndent -= 2
	}
}

func NewPrinter() *Printer {
	return &Printer{
		currentIndent: 0,
	}
}
