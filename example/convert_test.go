package main

import (
	"github.com/k0kubun/pp"
	"testing"
)

func TestConvert(t *testing.T) {
	var s = []string {"1", "2"}
	sample(s)
	pp.Println(s)
}

func sample(s []string) {
	s = append(s, "3")
}
