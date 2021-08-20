package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type Field struct {
	AccessFlag uint16
	NameIndex uint16
	DescriptorIndex uint16
	Attributes []Attribute
}

func (cf *ClassFile) readFields(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read fields count failed, no enough data in the stream")
	}

	var size = binary.BigEndian.Uint16(bs)
	for i := uint16(0); i < size; i++ {
		field, err := cf.readField(stream)
		if err != nil {
			return err
		}

		cf.Fields = append(cf.Fields, field)
	}

	return nil
}

func (cf *ClassFile) readField(stream *commons.Stream) (*Field, error) {
	var field = new(Field)
	bs, err := stream.ReadN(8)
	if err != nil {
		return nil, fmt.Errorf("read field access flag failed, no enough data in the stream")
	}
	field.AccessFlag = binary.BigEndian.Uint16(bs[:2])
	field.NameIndex = binary.BigEndian.Uint16(bs[2:4])
	field.DescriptorIndex = binary.BigEndian.Uint16(bs[4:6])
	var size = binary.BigEndian.Uint16(bs[6:])
	for i := uint16(0); i < size; i++ {
		attr, err := cf.readAttribute(stream)
		if err != nil {
			return nil, err
		}

		field.Attributes = append(field.Attributes, attr)
	}

	return field, nil
}
