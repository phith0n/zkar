package javaserialize

import "fmt"

type TCStringPointer struct {
	IsRef     bool
	String    *TCString
	Reference *TCReference
}

func (sp *TCStringPointer) ToBytes() []byte {
	if sp.IsRef {
		return sp.Reference.ToBytes()
	} else {
		return sp.String.ToBytes()
	}
}

func (sp *TCStringPointer) ToString() string {
	if sp.IsRef {
		return sp.Reference.ToString()
	} else {
		return sp.String.ToString()
	}
}

func readTCStringPointer(stream *ObjectStream) (*TCStringPointer, error) {
	flag, err := stream.PeekN(1)
	if err != nil {
		return nil, fmt.Errorf("read JAVA_TC_STRING pointer failed on index %v", stream.CurrentIndex())
	}

	var sp = TCStringPointer{
		IsRef: flag[0] != JAVA_TC_STRING,
	}
	if flag[0] == JAVA_TC_STRING {
		sp.String, err = readTCString(stream)
	} else {
		sp.Reference, err = readTCReference(stream)
	}

	if err != nil {
		return nil, err
	} else {
		return &sp, nil
	}
}
