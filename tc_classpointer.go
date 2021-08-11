package javaserialize

import (
	"fmt"
)

type TCClassPointer struct {
	Flag byte
	ClassDesc *TCClassDesc
	Null *TCNull
	Reference *TCReference
}

func (cp *TCClassPointer) ToBytes() []byte {
	var result []byte
	switch cp.Flag {
	case JAVA_TC_NULL:
		result = cp.Null.ToBytes()
	case JAVA_TC_REFERENCE:
		result = cp.Reference.ToBytes()
	case JAVA_TC_CLASSDESC:
		result = cp.ClassDesc.ToBytes()
	}

	return result
}

func (cp *TCClassPointer) GetClassDesc(stream *ObjectStream) (*TCClassDesc, error) {
	if cp.Flag == JAVA_TC_NULL {
		return nil, fmt.Errorf("JAVA_TC_NULL is not allowed here")
	} else if cp.Flag == JAVA_TC_CLASSDESC {
		return cp.ClassDesc, nil
	} else {
		obj := stream.GetReference(cp.Reference.Handler)
		if obj == nil {
			return nil, fmt.Errorf("JAVA_TC_REFERENCE handler not found")
		}

		if obj, ok := obj.(*TCClassDesc); ok {
			return obj, nil
		}

		return nil, fmt.Errorf("JAVA_TC_REFERENCE handler not found")
	}
}

func readTCClassPointer(stream *ObjectStream, bag *ClassBag) (*TCClassPointer, error) {
	// read JAVA_TC_CLASSDESC Flag
	flag, _ := stream.PeekN(1)
	if flag[0] == JAVA_TC_NULL {
		return &TCClassPointer{
			Flag: JAVA_TC_NULL,
			Null: readTCNull(stream),
		}, nil
	} else if flag[0] == JAVA_TC_REFERENCE {
		reference, err := readTCReference(stream)
		if err != nil {
			return nil, err
		}

		return &TCClassPointer{
			Flag: JAVA_TC_REFERENCE,
			Reference: reference,
		}, nil
	} else if flag[0] == JAVA_TC_CLASSDESC {
		desc, err := readTCClassDesc(stream, bag)
		if err != nil {
			return nil, err
		}

		return &TCClassPointer{
			Flag: JAVA_TC_CLASSDESC,
			ClassDesc: desc,
		}, nil
	} else {
		// TODO: TC_PROXYCLASSDESC
		return nil, fmt.Errorf("read ClassDesc failed in index %v", stream.CurrentIndex())
	}
}
