package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type StringObject struct {
	data []byte
}

func NewStringObject(data string) (*StringObject, error) {
	length := len(data)
	if length > 0xFFFF {
		return nil, fmt.Errorf("StringObject length must be less than 0xFFFF, but %v is given", length)
	}

	return &StringObject{
		data: []byte(data),
	}, nil
}

func NewString(data string) (Object, error) {
	length := len(data)
	if length <= 0xFFFF {
		return NewStringObject(data)
	} else {
		return NewLongStringObject(data)
	}
}

func (so *StringObject) ToBytes() []byte {
	var bs = []byte{JAVA_TC_STRING}
	var lengthBs = make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBs, uint16(len(so.data)))

	bs = append(bs, lengthBs...)
	return append(bs, so.data...)
}
