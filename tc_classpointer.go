package javaserialize

import "fmt"

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

func readTCClassPointer(stream *Stream) (*TCClassPointer, error) {
	// read JAVA_TC_CLASSDESC Flag
	flag, _ := stream.PeekN(1)
	if flag[0] == JAVA_TC_NULL {
		return &TCClassPointer{
			Flag: JAVA_TC_NULL,
			Null: readTCNull(stream),
		}, nil
	} else if flag[0] == JAVA_TC_REFERENCE {
		reference, err := readReference(stream)
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
