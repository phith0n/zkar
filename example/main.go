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

	ser, err := zkar.FromBytes(data)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// pp.Println(ser)
	// ioutil.WriteFile("testcases/ysoserial/C3P01.ser", ser.ToBytes(), fs.FileMode(755))
	fmt.Println(ser.ToString())
}
