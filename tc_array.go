package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type TCArray struct {
	TypeCode byte
	ClassPointer *TCClassPointer
	ArrayData []*TCValue
}

func (t *TCArray) ToBytes() []byte {
	var bs = []byte{JAVA_TC_ARRAY}
	bs = append(bs, t.ClassPointer.ToBytes()...)
	bs = append(bs, NumberToBytes(uint32(len(t.ArrayData)))...)
	for _, value := range t.ArrayData {
		bs = append(bs, value.ToBytes()...)
	}

	return bs
}

func readTCArray(stream *ObjectStream) (*TCArray, error) {
	var classes []*TCClassDesc
	var array = new(TCArray)
	var err error

	_, _ = stream.ReadN(1)
	array.ClassPointer, err = readTCClassPointer(stream, classes)
	if err != nil {
		return nil, err
	}

	bs, err := stream.ReadN(4)
	if err != nil {
		sugar.Error(err)
		return nil, fmt.Errorf("read JAVA_TC_ARRAY object failed on index %v", stream.CurrentIndex())
	}

	size := binary.BigEndian.Uint32(bs)
	for i := uint32(0); i < size; i++ {
		// TODO
	}

	return array, nil
}
