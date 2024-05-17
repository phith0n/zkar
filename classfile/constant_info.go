package classfile

const (
	ConstantClass              = 7
	ConstantFieldRef           = 9
	ConstantMethodRef          = 10
	ConstantInterfaceMethodRef = 11
	ConstantString             = 8
	ConstantInteger            = 3
	ConstantFloat              = 4
	ConstantLong               = 5
	ConstantDouble             = 6
	ConstantNameAndType        = 12
	ConstantUtf8               = 1
	ConstantMethodHandle       = 15
	ConstantMethodType         = 16
	ConstantInvokeDynamic      = 18
)

/*
cp_info {
    u1 tag;
    u1 info[];
}
*/

type ConstantInfo interface {
	readInfo(reader *ClassReader)
}

func readConstantInfo(reader *ClassReader, cp ConstantPool) ConstantInfo {
	tag := reader.readUint8()
	c := newConstantInfo(tag, cp)
	c.readInfo(reader)
	return c
}

func newConstantInfo(tag uint8, cp ConstantPool) ConstantInfo {
	switch tag {
	case ConstantInteger:
		return &ConstantIntegerInfo{}
	case ConstantFloat:
		return &ConstantFloatInfo{}
	case ConstantLong:
		return &ConstantLongInfo{}
	case ConstantDouble:
		return &ConstantDoubleInfo{}
	case ConstantUtf8:
		return &ConstantUtf8Info{}
	case ConstantString:
		return &ConstantStringInfo{cp: cp}
	case ConstantClass:
		return &ConstantClassInfo{cp: cp}
	case ConstantFieldRef:
		return &ConstantFieldRefInfo{ConstantMemberRefInfo{cp: cp}}
	case ConstantMethodRef:
		return &ConstantMethodRefInfo{ConstantMemberRefInfo{cp: cp}}
	case ConstantInterfaceMethodRef:
		return &ConstantInterfaceMethodRefInfo{ConstantMemberRefInfo{cp: cp}}
	case ConstantNameAndType:
		return &ConstantNameAndTypeInfo{}
	case ConstantMethodType:
		return &ConstantMethodTypeInfo{}
	case ConstantMethodHandle:
		return &ConstantMethodHandleInfo{}
	case ConstantInvokeDynamic:
		return &ConstantInvokeDynamicInfo{}
	default:
		panic("java.lang.ClassFormatError: constant pool tag!")
	}
}
