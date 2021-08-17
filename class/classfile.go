package class

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ClassFile struct {
	MagicNumber []byte
	MinorVersion uint16
	MajorVersion uint16
	ConstantPool []Constant
	AccessFlag uint16
	ThisClassOffset uint16
	SuperClassOffset uint16
	InterfaceOffsetArray []uint16
	Fields []*Field
	Methods []*Method
	Attributes []*Attribute
}

func (cf *ClassFile) readHeader(stream *commons.Stream) error {
	bs, err := stream.ReadN(4)
	if err != nil {
		return fmt.Errorf("read magic number failed, no enough data in the stream")
	}

	if !bytes.Equal(bs, []byte("\xCA\xFE\xBA\xBE")) {
		return fmt.Errorf("magic number %v is not equal to CAFEBABE", hex.EncodeToString(bs))
	}

	cf.MagicNumber = bs
	bs, err = stream.ReadN(4)
	if err != nil {
		return fmt.Errorf("read minor and major version failed, no enough data in the stream")
	}

	cf.MinorVersion = binary.BigEndian.Uint16(bs[:2])
	cf.MajorVersion = binary.BigEndian.Uint16(bs[2:])
	return nil
}

func (cf *ClassFile) readConstantPool(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read constant pool size failed, no enough data in the stream")
	}

	var size = binary.BigEndian.Uint16(bs)

	// Note: Constant Pool index is start from 1, not 0
	for i := uint16(1); i < size; i++ {
		err = cf.readConstantPool(stream)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cf *ClassFile) readConstant(stream *commons.Stream) error {
	bs, err := stream.PeekN(1)
	if err != nil {
		return fmt.Errorf("read constant type failed, no enough data in the stream")
	}

	var obj Constant
	switch bs[0] {
	case CONSTANT_UTF8_INFO:
		obj, err = readConstantUTF8(stream)
	case CONSTANT_INTEGER_INFO:
		obj, err = readConstantInteger(stream)
	case CONSTANT_FLOAT_INFO:
		obj, err = readConstantFloat(stream)
	case CONSTANT_LONG_INFO:
		obj, err = readConstantLong(stream)
	case CONSTANT_DOUBLE_INFO:
		obj, err = readConstantDouble(stream)
	case CONSTANT_CLASS_INFO:
		obj, err = readConstantClass(stream)
	case CONSTANT_STRING_INGFO:
		obj, err = readConstantString(stream)
	}

	if err != nil {
		return err
	}

	cf.ConstantPool = append(cf.ConstantPool, obj)
	return nil
}
