package main

import (
	"fmt"
	"github.com/phith0n/zkar/serz"
	"io/ioutil"
	"log"
)

func main() {
	data, _ := ioutil.ReadFile("./testcases/ysoserial/Jdk7u21.ser")
	serialization, err := serz.FromBytes(data)
	if err != nil {
		log.Fatal("parse error")
	}

	desc := serz.FindClassDesc(serialization, "sun.reflect.annotation.AnnotationInvocationHandler")
	if desc != nil {
		fmt.Println(desc.ToString())
	} else {
		log.Fatal("class desc not found")
	}
}
