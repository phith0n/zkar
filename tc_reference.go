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

	for pair := stream.References().Oldest(); pair != nil; pair.Next() {
		// TODO: TC_PROXYCLASSDESC and TC_ENUM
		if pair.Key == handler {
			switch obj := pair.Value.(type) {
			case *TCClass:
				reference.Class = obj
			case *TCClassDesc:
				reference.ClassDesc = obj
			case *TCString:
				reference.String = obj
			case *TCArray:
				reference.Array = obj
			default:
				goto Failed
			}

			reference.ClassDesc = pair.Value.(*TCClassDesc)
			return reference, nil
		}
	}

Failed:
	return nil, fmt.Errorf("object reference %v is not found", handler)
}
