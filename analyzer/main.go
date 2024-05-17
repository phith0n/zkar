package main

import (
	"fmt"
	"log"
	"os"

	"github.com/phith0n/zkar/serz"
)

func main() {
	data, _ := os.ReadFile("./testcases/ysoserial/CommonsBeanutils1.ser")
	serialization, err := serz.FromBytes(data)
	if err != nil {
		log.Fatal("parse error")
	}

	err = serialization.Walk(func(object serz.Object) error {
		v, ok := object.(*serz.TCArray)
		if ok {
			if len(v.ArrayData) > 0 {
				if v.ArrayData[0].TypeCode == "B" {
					fmt.Println(v.ToString())
				}
			}
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
}
