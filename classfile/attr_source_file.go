package classfile

/*
SourceFile_attribute {
    u2 attribute_name_index;
    u4 attribute_length;
    u2 sourcefile_index;
}
*/

type SourceFileAttribute struct {
	cp              ConstantPool
	sourceFileIndex uint16
}

func (c *SourceFileAttribute) readInfo(reader *ClassReader) {
	c.sourceFileIndex = reader.readUint16()
}

func (c *SourceFileAttribute) FileName() string {
	return c.cp.GetUtf8(c.sourceFileIndex)
}
