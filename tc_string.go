package javaserialize

import (
	"fmt"
)

type TCString struct {
	Utf *TCUtf
}

func (so *TCString) ToBytes() []byte {
	var bs []byte
	length := len(so.Utf.Data)
	if length <= 0xFFFF {
		bs = append(bs, JAVA_TC_STRING)
	} else {
		bs = append(bs, JAVA_TC_LONGSTRING)
	}

	return append(bs, so.Utf.ToBytes()...)
}

func readTCString(stream *ObjectStream) (*TCString, error) {
	var s = new(TCString)
	var err error
	flag, _ := stream.ReadN(1)
	if flag[0] == JAVA_TC_STRING {
		s.Utf, err = readUTF(stream)
	} else if flag[0] == JAVA_TC_LONGSTRING {
		s.Utf, err = readLongUTF(stream)
	} else {
		return nil, fmt.Errorf("readTCString flag error on index %v", stream.CurrentIndex())
	}

	if err != nil {
		return nil, err
	}

	stream.AddReference(s)
	return s, nil
}
