package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type TCLongString struct {
	data []byte
}

func (so *TCLongString) ToBytes() []byte {
	var bs = []byte{JAVA_TC_STRING}
	bs = append(bs, NumberToBytes(uint64(len(so.data)))...)
	return append(bs, so.data...)
}

func NewTCLongString(data string) *TCLongString {
	return &TCLongString{
		data: []byte(data),
	}
}

func readTCLongString(stream *Stream) (*TCLongString, error) {
	var bs []byte
	var err error

	// read JAVA_TC_LONGSTRING Flag, 0x77
	_, _ = stream.ReadN(1)

	// read JAVA_TC_LONGSTRING object length, uint16
	bs, err = stream.ReadN(8)
	if err != nil {
		sugar.Error(err)
		return nil, fmt.Errorf("read JAVA_TC_LONGSTRING object failed on index %v", stream.CurrentIndex())
	}

	length := binary.BigEndian.Uint64(bs)
	if length > 0xFFFFFFFF {
		return nil, fmt.Errorf("javaserialize doesn't support JAVA_TC_LONGSTRING longer than 0xFFFFFFFF, but current length is %v", length)
	}

	data, err := stream.ReadN(int(length))
	if err != nil {
		sugar.Error(err)
		return nil, fmt.Errorf("read JAVA_TC_LONGSTRING object failed on index %v", stream.CurrentIndex())
	}

	return &TCLongString{
		data: data,
	}, nil
}
