package main

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestConvert(t *testing.T) {
	var r rune = '你'
	var bs = make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(r))
	fmt.Println(bs)
}
