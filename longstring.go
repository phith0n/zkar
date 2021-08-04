package javaserialize

import (
	"encoding/binary"
)

type LongStringObject struct {
	data []byte
}

func NewLongStringObject(data string) (*LongStringObject, error) {
	return &LongStringObject{
		data: []byte(data),
	}, nil
}

func (so *LongStringObject) ToBytes() []byte {
	var bs = []byte{JAVA_TC_STRING}
	var lengthBs = make([]byte, 8)
	binary.BigEndian.PutUint64(lengthBs, uint64(len(so.data)))

	bs = append(bs, lengthBs...)
	return append(bs, so.data...)
}
