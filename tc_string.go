package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type TCString struct {
	data []byte
}

func (so *TCString) ToBytes() []byte {
	var bs = []byte{JAVA_TC_STRING}
	bs = append(bs, NumberToBytes(uint16(len(so.data)))...)
	return append(bs, so.data...)
}


func NewTCString(data string) (*TCString, error) {
	length := len(data)
	if length > 0xFFFF {
		return nil, fmt.Errorf("TCString length must be less than 0xFFFF, but %v is given", length)
	}

	return &TCString{
		data: []byte(data),
	}, nil
}

func NewSmartTCString(data string) (Object, error) {
	length := len(data)
	if length <= 0xFFFF {
		return NewTCString(data)
	} else {
		return NewTCLongString(data), nil
	}
}

func readTCString(stream *Stream) (*TCString, error) {
	// read JAVA_TC_STRING Flag, 0x74
	_, _ = stream.ReadN(1)

	return readUTF(stream)
}

func readUTF(stream *Stream) (*TCString, error) {
	var bs []byte
	var err error

	// read JAVA_TC_STRING object length, uint16
	bs, err = stream.ReadN(2)
	if err != nil {
		sugar.Error(err)
		return nil, fmt.Errorf("read JAVA_TC_STRING object failed on index %v", stream.CurrentIndex())
	}

	// read JAVA_TC_STRING object
	length := binary.BigEndian.Uint16(bs)
	data, err := stream.ReadN(int(length))
	if err != nil {
		sugar.Error(err)
		return nil, fmt.Errorf("read JAVA_TC_STRING object failed on index %v", stream.CurrentIndex())
	}

	return &TCString{
		data: data,
	}, nil
}
