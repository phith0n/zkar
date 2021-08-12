package main

import (
	"fmt"
	"github.com/k0kubun/pp"
	"github.com/phith0n/javaserialize"
	"io/ioutil"
)

func main() {
	data, err := ioutil.ReadFile("example/enum.poc")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	os := javaserialize.NewObjectInputStream()
	err = os.Read(data)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	pp.Println(os)
}
