package main

import (
	"fmt"
	"github.com/phith0n/zkar"
	"io/ioutil"
)

func main() {
	// var filename = "testcases/ysoserial/class.ser"
	var filename = "example/object.poc"
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	os := zkar.NewObjectInputStream()
	err = os.Read(data)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// pp.Println(os)
	// ioutil.WriteFile("testcases/ysoserial/C3P01.ser", os.ToBytes(), fs.FileMode(755))
	fmt.Println(os.ToString())
}
