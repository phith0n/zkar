package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type TCString struct {
	data []byte
}

func (so *TCString) ToBytes() []byte {
	var bs []byte
	length := len(so.data)
	if length <= 0xFFFF {
		bs = append(bs, JAVA_TC_STRING)
		bs = append(bs, NumberToBytes(uint16(len(so.data)))...)
	} else {
		bs = append(bs, JAVA_TC_LONGSTRING)
		bs = append(bs, NumberToBytes(uint64(len(so.data)))...)
	}

	return append(bs, so.data...)
}

func readTCString(stream *ObjectStream) (*TCString, error) {
	flag, err := stream.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("readTCString failed on index %v", stream.CurrentIndex())
	}

	if flag[0] != JAVA_TC_STRING && flag[0] != JAVA_TC_LONGSTRING {
		return nil, fmt.Errorf("readTCString flag error on index %v", stream.CurrentIndex())
	}

	if flag[0] == JAVA_TC_STRING {
		return readUTF(stream)
	}

	// read JAVA_TC_LONGSTRING object length, uint16
	bs, err := stream.ReadN(8)
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

	obj := &TCString{
		data: data,
	}
	stream.AddReference(obj)
	return obj, nil
}

func readUTF(stream *ObjectStream) (*TCString, error) {
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
