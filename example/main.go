package main

import (
	"encoding/hex"
	"fmt"
)

func main() {
	var s = "\x8c\xA3\x8B"
	var bs = []byte(s)
	fmt.Println(bs, s, hex.EncodeToString(bs))
}
