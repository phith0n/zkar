package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type TCReference struct {
	handler uint32
}

func (r *TCReference) ToBytes() []byte {
	bs := NumberToBytes(r.handler)
	result := []byte{JAVA_TC_REFERENCE}
	return append(result, bs...)
}

func readReference(stream *Stream) (*TCReference, error) {
	// read JAVA_TC_REFERENCE flag
	_, _ = stream.ReadN(1)

	bs, err := stream.ReadN(4)
	if err != nil {
		sugar.Error(err)
		return nil, fmt.Errorf("read JAVA_TC_REFERENCE failed on index %v", stream.CurrentIndex())
	}

	handler := binary.BigEndian.Uint32(bs)

	return &TCReference{
		handler: handler,
	}, nil
}
