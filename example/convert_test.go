package main

import (
	"fmt"
	"testing"
)

func TestConvert(t *testing.T) {
	var i int8 = -55
	var bs = make([]byte, 1)
	bs[0] = uint8(i)

	fmt.Println(bs, int8(bs[0]))
}
