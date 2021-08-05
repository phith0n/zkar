package main

import (
	"encoding/hex"
	"fmt"
	"github.com/phith0n/javaserialize"
	"testing"
)

func TestConvert(t *testing.T) {
	var i int16 = -2324
	fmt.Println(hex.EncodeToString(javaserialize.NumberToBytes(i)))
}
