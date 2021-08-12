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

func (cp *TCClassPointer) FindClassBag(stream *ObjectStream) (*ClassBag, error) {
	var desc *TCClassDesc
	var err error
	if cp.Flag == JAVA_TC_NULL {
		return nil, nil
	}

	desc, err = cp.GetClassDesc(stream)
	if err != nil {
		return nil, err
	}

	var bag = &ClassBag{
		Classes: []*TCClassDesc{desc},
	}

	newBag, err := desc.SuperClassPointer.FindClassBag(stream)
	if err != nil {
		return nil, err
	}

	if newBag != nil {
		bag.Merge(newBag)
	}

	return bag, nil
}

func readTCClassPointer(stream *ObjectStream) (*TCClassPointer, error) {
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
		desc, err := readTCClassDesc(stream)
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
