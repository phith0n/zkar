package main

import (
	"fmt"
	"github.com/phith0n/javaserialize"
	"io/ioutil"
)

func main() {
	data, err := ioutil.ReadFile("example/example.poc")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	os := &javaserialize.ObjectStream{}
	err = os.ReadObject(data)
	if err != nil {
		fmt.Println(err.Error())
	}
}
