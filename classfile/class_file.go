package classfile

import "fmt"

/*
classfile {
    u4             magic;
    u2             minor_version;
    u2             major_version;
    u2             constant_pool_count;
    cp_info        constant_pool[constant_pool_count-1];
    u2             access_flags;
    u2             this_class;
    u2             super_class;
    u2             interfaces_count;
    u2             interfaces[interfaces_count];
    u2             fields_count;
    field_info     fields[fields_count];
    u2             methods_count;
    method_info    methods[methods_count];
    u2             attributes_count;
    attribute_info attributes[attributes_count];
}
*/

type ClassFile struct {
	magic        uint32
	minorVersion uint16
	majorVersion uint16
	constantPool ConstantPool
	accessFlags  uint16
	thisClass    uint16
	superClass   uint16
	interfaces   []uint16
	fields       []*MemberInfo
	methods      []*MemberInfo
	attributes   []AttributeInfo
}

func Parse(classData []byte) (cf *ClassFile, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("%v", r)
			}
		}
	}()
	cr := &ClassReader{classData}
	cf = &ClassFile{}
	cf.read(cr)
	return
}

func (c *ClassFile) read(reader *ClassReader) {
	c.readAndCheckMagic(reader)
	c.readAndCheckVersion(reader)
	c.constantPool = readConstantPool(reader)
	c.accessFlags = reader.readUint16()
	c.thisClass = reader.readUint16()
	c.superClass = reader.readUint16()
	c.interfaces = reader.readUint16s()
	c.fields = readMembers(reader, c.constantPool)
	c.methods = readMembers(reader, c.constantPool)
	c.attributes = readAttributes(reader, c.constantPool)
}

func (c *ClassFile) readAndCheckMagic(reader *ClassReader) {
	magic := reader.readUint32()
	if magic != 0xCAFEBABE {
		panic("java.lang.ClassFormatError: magic!")
	}
	c.magic = magic
}

func (c *ClassFile) readAndCheckVersion(reader *ClassReader) {
	c.minorVersion = reader.readUint16()
	c.majorVersion = reader.readUint16()
	switch c.majorVersion {
	case 45:
		// JDK 1.0.2
		return
	case 46, 47, 48, 49, 50, 51, 52:
		// JDK 1.2 - JDK 1.8
		if c.minorVersion == 0 {
			return
		}
	}
	panic("java.lang.UnsupportedClassVersionError!")
}

func (c *ClassFile) MinorVersion() uint16 {
	return c.minorVersion
}

func (c *ClassFile) MajorVersion() uint16 {
	return c.majorVersion
}

func (c *ClassFile) ConstantPool() ConstantPool {
	return c.constantPool
}

func (c *ClassFile) AccessFlags() uint16 {
	return c.accessFlags
}

func (c *ClassFile) Fields() []*MemberInfo {
	return c.fields
}

func (c *ClassFile) Methods() []*MemberInfo {
	return c.methods
}

func (c *ClassFile) ClassName() string {
	return c.constantPool.GetClassName(c.thisClass)
}

func (c *ClassFile) SuperClassName() string {
	if c.superClass > 0 {
		return c.constantPool.GetClassName(c.superClass)
	}
	return ""
}

func (c *ClassFile) InterfaceNames() []string {
	interfaceNames := make([]string, len(c.interfaces))
	for i, cpIndex := range c.interfaces {
		interfaceNames[i] = c.constantPool.GetClassName(cpIndex)
	}
	return interfaceNames
}
