package main

import (
	"fmt"
	"github.com/phith0n/zkar/serz"
	"log"
	"os"
)

func main() {
	fs, err := os.Open("./testcases/ysoserial/Jdk7u21.ser")
	if err != nil {
		log.Fatal(err)
	}
	defer fs.Close()

	serialization, err := serz.FromReader(fs)
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
