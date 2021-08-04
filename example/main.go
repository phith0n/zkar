package main

import (
	"encoding/hex"
	"fmt"
	"github.com/phith0n/javaserialize"
	"io/ioutil"
)

func main() {
	data, err := ioutil.ReadFile("example/string.poc")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	os := javaserialize.NewObjectInputStream()
	err = os.ReadObject(data)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	for _, o := range os.Objects {
		fmt.Println(hex.EncodeToString(o.ToBytes()))
	}
}
