package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type TCReference struct {
	Handler uint32
	Flag byte
	Object *TCObject
	Class *TCClass
	NormalClassDesc *TCClassDesc
	ProxyClassDesc *TCProxyClassDesc
	String *TCString
	Array *TCArray
	Enum *TCEnum
}

func (r *TCReference) ToBytes() []byte {
	result := []byte{JAVA_TC_REFERENCE}
	bs := NumberToBytes(r.Handler)
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
		switch obj := obj.(type) {
		case *TCObject:
			reference.Flag = JAVA_TC_OBJECT
			reference.Object = obj
		case *TCClass:
			reference.Flag = JAVA_TC_CLASS
			reference.Class = obj
		case *TCClassDesc:
			reference.Flag = JAVA_TC_CLASSDESC
			reference.NormalClassDesc = obj
		case *TCProxyClassDesc:
			reference.Flag = JAVA_TC_PROXYCLASSDESC
			reference.ProxyClassDesc = obj
		case *TCString:
			reference.Flag = JAVA_TC_STRING
			reference.String = obj
		case *TCArray:
			reference.Flag = JAVA_TC_ARRAY
			reference.Array = obj
		case *TCEnum:
			reference.Flag = JAVA_TC_ENUM
			reference.Enum = obj
		default:
			goto Failed
		}

		return reference, nil
	}

Failed:
	return nil, fmt.Errorf("object reference %v is not found on index %v", handler, stream.CurrentIndex())
}
