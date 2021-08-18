package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

const (
	CONSTANT_UTF8_INFO            = 1
	CONSTANT_INTEGER_INFO         = 3
	CONSTANT_FLOAT_INFO           = 4
	CONSTANT_LONG_INFO            = 5
	CONSTANT_DOUBLE_INFO          = 6
	CONSTANT_CLASS_INFO           = 7
	CONSTANT_STRING_INGFO         = 8
	CONSTANT_FIELD_REF_INFO       = 9
	CONSTANT_METHOD_REF_INFO      = 10
	CONSTANT_INTERFACE_METHOD_REF = 11
	CONSTANT_NAME_AND_TYPE_INFO   = 12
	CONSTANT_METHOD_HANDLE_INFO   = 15
	CONSTANT_METHOD_TYPE_INFO     = 16
	CONSTANT_DYNAMIC_INFO         = 17
	CONSTANT_INVOKE_DYNAMIC_INFO  = 18
	CONSTANT_MODULE_INFO          = 19
	CONSTANT_PACKAGE_INFO         = 20
)

type Constant interface {
	ToBytes() []byte
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
	case CONSTANT_METHOD_HANDLE_INFO:
		obj, err = readConstantMethodHandle(stream)
	case CONSTANT_METHOD_TYPE_INFO:
		obj, err = readConstantMethodType(stream)
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

