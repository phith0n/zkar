package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type Attribute interface {
	readInfo(stream *commons.Stream) error
}

type AttributeBase struct {
	class *ClassFile

	AttributeNameIndex uint16
	AttributeLength    uint32
}

func newAttributeBase(class *ClassFile, nameIndex uint16, length uint32) *AttributeBase {
	return &AttributeBase{
		class: class,
		AttributeNameIndex: nameIndex,
		AttributeLength: length,
	}
}

func (cf *ClassFile) readAttribute(stream *commons.Stream) (Attribute, error) {
	bs, err := stream.ReadN(6)
	if err != nil {
		return nil, fmt.Errorf("read attribute failed, no enough data in the stream")
	}

	nameIndex := binary.BigEndian.Uint16(bs[:2])
	length := binary.BigEndian.Uint32(bs[2:])

	var utf8 *ConstantUTF8
	var ok bool
	if utf8, ok = cf.ConstantPool[nameIndex].(*ConstantUTF8); !ok {
		return nil, fmt.Errorf("attribute name index must be a ConstantUTF8 reference")
	}

	var attr Attribute
	switch utf8.Data {
	case "SourceFile":
		attr = &AttrSourceFile{AttributeBase: newAttributeBase(cf, nameIndex, length)}
	}

	err = attr.readInfo(stream)
	if err != nil {
		return nil, err
	}

	return attr, nil
}
