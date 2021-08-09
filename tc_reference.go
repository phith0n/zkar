package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type TCReference struct {
	Handler uint32
	ClassDesc *TCClassDesc
}

func (r *TCReference) ToBytes() []byte {
	bs := NumberToBytes(r.Handler)
	result := []byte{JAVA_TC_REFERENCE}
	return append(result, bs...)
}

func readReference(stream *ObjectStream) (*TCReference, error) {
	// read JAVA_TC_REFERENCE flag
	_, _ = stream.ReadN(1)

	bs, err := stream.ReadN(4)
	if err != nil {
		sugar.Error(err)
		return nil, fmt.Errorf("read JAVA_TC_REFERENCE failed on index %v", stream.CurrentIndex())
	}

	handler := binary.BigEndian.Uint32(bs)
	reference := &TCReference{
		Handler: handler,
	}

	for pair := stream.GetBag().Oldest(); pair != nil; pair.Next() {
		if pair.Key == handler {
			reference.ClassDesc = pair.Value.(*TCClassDesc)
			return reference, nil
		}
	}

	return nil, fmt.Errorf("object reference %v is not found", handler)
}
