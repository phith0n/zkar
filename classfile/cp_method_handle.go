package classfile

/*
CONSTANT_MethodHandle_info {
    u1 tag;
    u1 reference_kind;
    u2 reference_index;
}
*/

type ConstantMethodHandleInfo struct {
	referenceKind  uint8
	referenceIndex uint16
}

func (c *ConstantMethodHandleInfo) readInfo(reader *ClassReader) {
	c.referenceKind = reader.readUint8()
	c.referenceIndex = reader.readUint16()
}
