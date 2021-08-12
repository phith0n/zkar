package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type TCReference struct {
	Handler uint32
	Class *TCClass
	ClassDesc *TCClassDesc
	String *TCString
	Array *TCArray
	Enum *TCEnum
}

func (r *TCReference) ToBytes() []byte {
	bs := NumberToBytes(r.Handler)
	result := []byte{JAVA_TC_REFERENCE}
	return append(result, bs...)
}

func readTCReference(stream *ObjectStream) (*TCReference, error) {
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

	obj := stream.GetReference(handler)
	if obj != nil {
		// TODO: TC_PROXYCLASSDESC
		switch obj := obj.(type) {
		case *TCClass:
			reference.Class = obj
		case *TCClassDesc:
			reference.ClassDesc = obj
		case *TCString:
			reference.String = obj
		case *TCArray:
			reference.Array = obj
		case *TCEnum:
			reference.Enum = obj
		default:
			goto Failed
		}

		return reference, nil
	}

Failed:
	return nil, fmt.Errorf("object reference %v is not found on index %v", handler, stream.CurrentIndex())
}
