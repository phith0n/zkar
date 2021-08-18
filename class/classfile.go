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
	ThisClassIndex uint16
	SuperClassIndex uint16
	InterfaceIndexArray []uint16
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
		err = cf.readConstant(stream)
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
	case CONSTANT_FIELD_REF_INFO:
		obj, err = readConstantFieldRef(stream)
	case CONSTANT_METHOD_REF_INFO:
		obj, err = readConstantMethodRef(stream)
	case CONSTANT_INTERFACE_METHOD_REF:
		obj, err = readConstantInterfaceMethodRef(stream)
	case CONSTANT_NAME_AND_TYPE_INFO:
		obj, err = readConstantNameAndType(stream)
	case CONSTANT_DYNAMIC_INFO:
		obj, err = readConstantDynamic(stream)
	case CONSTANT_INVOKE_DYNAMIC_INFO:
		obj, err = readConstantInvokeDynamic(stream)
	case CONSTANT_MODULE_INFO:
		obj, err = readConstantModule(stream)
	case CONSTANT_PACKAGE_INFO:
		obj, err = readConstantPackage(stream)
	default:
		err = fmt.Errorf("constant type %v doesn't exists", bs)
	}

	if err != nil {
		return err
	}

	cf.ConstantPool = append(cf.ConstantPool, obj)
	return nil
}
