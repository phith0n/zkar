package serialization

import (
	"encoding/binary"
	"fmt"
)

type TCUtf struct {
	Data string
}

func (u *TCUtf) ToBytes() []byte {
	var bs []byte
	var length = len(u.Data)
	if length <= 0xFFFF {
		bs = NumberToBytes(uint16(len(u.Data)))
	} else {
		bs = NumberToBytes(uint64(len(u.Data)))
	}

	return append(bs, []byte(u.Data)...)
}

func (u *TCUtf) ToString() string {
	var b = newPrinter()
	var length = len(u.Data)
	var bs []byte
	if length <= 0xFFFF {
		bs = NumberToBytes(uint16(len(u.Data)))
	} else {
		bs = NumberToBytes(uint64(len(u.Data)))
	}

	b.printf("@Length - %d - %s", len(u.Data), Hexify(bs))
	b.printf("@Value - %s - %s", u.Data, Hexify(u.Data))
	return b.String()
}

func readUTF(stream *ObjectStream) (*TCUtf, error) {
	var bs []byte
	var err error

	// read JAVA_TC_STRING object length, uint16
	bs, err = stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read JAVA_TC_STRING object failed on index %v", stream.CurrentIndex())
	}

	// read JAVA_TC_STRING object
	length := binary.BigEndian.Uint16(bs)
	data, err := stream.ReadN(int(length))
	if err != nil {
		return nil, fmt.Errorf("read JAVA_TC_STRING object failed on index %v", stream.CurrentIndex())
	}

	return &TCUtf{
		Data: string(data),
	}, nil
}

func readLongUTF(stream *ObjectStream) (*TCUtf, error) {
	// read JAVA_TC_LONGSTRING object length, uint16
	bs, err := stream.ReadN(8)
	if err != nil {
		return nil, fmt.Errorf("read JAVA_TC_LONGSTRING object failed on index %v", stream.CurrentIndex())
	}

	length := binary.BigEndian.Uint64(bs)
	if length > 0xFFFFFFFF {
		return nil, fmt.Errorf("zkar doesn't support JAVA_TC_LONGSTRING longer than 0xFFFFFFFF, but current length is %v", length)
	}

	data, err := stream.ReadN(int(length))
	if err != nil {
		return nil, fmt.Errorf("read JAVA_TC_LONGSTRING object failed on index %v", stream.CurrentIndex())
	}

	return &TCUtf{
		Data: string(data),
	}, nil
}
