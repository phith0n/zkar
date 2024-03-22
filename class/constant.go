package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

const (
	ConstantUtf8Info               = 1
	ConstantIntegerInfo            = 3
	ConstantFloatInfo              = 4
	ConstantLongInfo               = 5
	ConstantDoubleInfo             = 6
	ConstantClassInfo              = 7
	ConstantStringInfo             = 8
	ConstantFieldRefInfo           = 9
	ConstantMethodRefInfo          = 10
	ConstantInterfaceMethodRefInfo = 11
	ConstantNameAndTypeInfo        = 12
	ConstantMethodHandleInfo       = 15
	ConstantMethodTypeInfo         = 16
	ConstantDynamicInfo            = 17
	ConstantInvokeDynamicInfo      = 18
	ConstantModuleInfo             = 19
	ConstantPackageInfo            = 20
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
	case ConstantUtf8Info:
		obj, err = cf.readConstantUTF8(stream)
	case ConstantIntegerInfo:
		obj, err = cf.readConstantInteger(stream)
	case ConstantFloatInfo:
		obj, err = cf.readConstantFloat(stream)
	case ConstantLongInfo:
		obj, err = cf.readConstantLong(stream)
	case ConstantDoubleInfo:
		obj, err = cf.readConstantDouble(stream)
	case ConstantClassInfo:
		obj, err = cf.readConstantClass(stream)
	case ConstantStringInfo:
		obj, err = cf.readConstantString(stream)
	case ConstantFieldRefInfo:
		obj, err = cf.readConstantFieldRef(stream)
	case ConstantMethodRefInfo:
		obj, err = cf.readConstantMethodRef(stream)
	case ConstantInterfaceMethodRefInfo:
		obj, err = cf.readConstantInterfaceMethodRef(stream)
	case ConstantNameAndTypeInfo:
		obj, err = cf.readConstantNameAndType(stream)
	case ConstantMethodHandleInfo:
		obj, err = cf.readConstantMethodHandle(stream)
	case ConstantMethodTypeInfo:
		obj, err = cf.readConstantMethodType(stream)
	case ConstantDynamicInfo:
		obj, err = cf.readConstantDynamic(stream)
	case ConstantInvokeDynamicInfo:
		obj, err = cf.readConstantInvokeDynamic(stream)
	case ConstantModuleInfo:
		obj, err = cf.readConstantModule(stream)
	case ConstantPackageInfo:
		obj, err = cf.readConstantPackage(stream)
	default:
		err = fmt.Errorf("constant type %v doesn't exists", bs)
	}

	if err != nil {
		return err
	}

	cf.ConstantPool = append(cf.ConstantPool, obj)
	return nil
}
