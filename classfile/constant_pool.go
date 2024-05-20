package classfile

import "fmt"

type ConstantPool []ConstantInfo

func readConstantPool(reader *ClassReader) ConstantPool {
	cpCount := int(reader.readUint16())
	cp := make([]ConstantInfo, cpCount)
	for i := 1; i < cpCount; i++ {
		cp[i] = readConstantInfo(reader, cp)
		switch cp[i].(type) {
		case *ConstantLongInfo, *ConstantDoubleInfo:
			i++
		}
	}
	return cp
}

func (c ConstantPool) GetConstantInfo(index uint16) ConstantInfo {
	if cpInfo := c[index]; cpInfo != nil {
		return cpInfo
	}
	panic(fmt.Errorf("invalid constant pool index: %v", index))
}

func (c ConstantPool) GetNameAndType(index uint16) (string, string) {
	ntInfo := c.GetConstantInfo(index).(*ConstantNameAndTypeInfo)
	name := c.GetUtf8(ntInfo.nameIndex)
	_type := c.GetUtf8(ntInfo.descriptorIndex)
	return name, _type
}

func (c ConstantPool) GetClassName(index uint16) string {
	classInfo := c.GetConstantInfo(index).(*ConstantClassInfo)
	return c.GetUtf8(classInfo.nameIndex)
}

func (c ConstantPool) GetUtf8(index uint16) string {
	utf8Info := c.GetConstantInfo(index).(*ConstantUtf8Info)
	return utf8Info.str
}
