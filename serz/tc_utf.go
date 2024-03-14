package serz

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type OverlongOption int

const (
	OverlongEncodingTwoBytes   OverlongOption = 2
	OverlongEncodingThreeBytes OverlongOption = 3
)

type TCUtf struct {
	Data string

	OverlongSize OverlongOption
}

func (u *TCUtf) ToBytes() []byte {
	var data []byte
	if u.OverlongSize == OverlongEncodingTwoBytes || u.OverlongSize == OverlongEncodingThreeBytes {
		data = toOverlongEncoding([]byte(u.Data), u.OverlongSize)
	} else {
		data = []byte(u.Data)
	}

	var length []byte
	if len(data) <= 0xFFFF {
		length = commons.NumberToBytes(uint16(len(data)))
	} else {
		length = commons.NumberToBytes(uint64(len(data)))
	}

	return append(length, data...)
}

func (u *TCUtf) ToString() string {
	var b = commons.NewPrinter()
	var length = len(u.Data)
	var bs []byte
	if length <= 0xFFFF {
		bs = commons.NumberToBytes(uint16(len(u.Data)))
	} else {
		bs = commons.NumberToBytes(uint64(len(u.Data)))
	}

	b.Printf("@Length - %d - %s", len(u.Data), commons.Hexify(bs))
	b.Printf("@Value - %s - %s", u.Data, commons.Hexify(u.Data))
	return b.String()
}

func (u *TCUtf) Walk(callback WalkCallback) error {
	return nil
}

func (u *TCUtf) SetOverlongSize(size OverlongOption) {
	u.OverlongSize = size
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
		Data: string(fromOverlongEncoding(data)),
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
		Data: string(fromOverlongEncoding(data)),
	}, nil
}

func toOverlongEncoding(data []byte, size OverlongOption) []byte {
	var bs []byte
	for _, ch := range data {
		if size == OverlongEncodingTwoBytes {
			bs = append(bs, ((ch>>6)&0b11111)|0b11000000)
			bs = append(bs, (ch&0b111111)|0b10000000)
		} else {
			bs = append(bs, 0b11100000)
			bs = append(bs, (ch>>6&0b111111)|0b10000000)
			bs = append(bs, (ch&0b111111)|0b10000000)
		}
	}

	return bs
}

func fromOverlongEncoding(data []byte) []byte {
	var rs []byte
	for i := 0; i < len(data); {
		b1 := data[i]
		i++
		if i < len(data) && b1>>5 == 0b110 {
			b2 := data[i]
			if b1>>1 == 0b1100000 && b2>>6 == 0b10 {
				rs = append(rs, (b2&0b111111)|(b1<<6))
				i++
				continue
			}
		} else if i+1 < len(data) && b1>>4 == 0b1110 {
			b2 := data[i]
			b3 := data[i+1]

			if b1 == 0b11100000 && b2>>1 == 0b1000000 && b3>>6 == 0b10 {
				rs = append(rs, (b3&0b111111)|(b2<<6))
				i += 2
				continue
			}
		}

		rs = append(rs, b1)
	}
	return rs
}
