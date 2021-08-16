package zkar

import (
	"fmt"
)

type TCString struct {
	Utf *TCUtf
	Handler uint32
}

func (so *TCString) ToBytes() []byte {
	var bs []byte
	var length = len(so.Utf.Data)
	if length <= 0xFFFF {
		bs = append(bs, JAVA_TC_STRING)
	} else {
		bs = append(bs, JAVA_TC_LONGSTRING)
	}

	return append(bs, so.Utf.ToBytes()...)
}

func (so *TCString) ToString() string {
	var b = newPrinter()
	var length = len(so.Utf.Data)
	if length <= 0xFFFF {
		b.printf("TC_STRING - %s", Hexify(JAVA_TC_STRING))
	} else {
		b.printf("TC_LONGSTRING - %s", Hexify(JAVA_TC_LONGSTRING))
	}
	b.increaseIndent()
	b.printf("@Handler - %v", so.Handler)
	b.print(so.Utf.ToString())
	return b.String()
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
