package classfile

/*
Signature_attribute {
    u2 attribute_name_index;
    u4 attribute_length;
    u2 signature_index;
}
*/

type SignatureAttribute struct {
	cp             ConstantPool
	signatureIndex uint16
}

func (c *SignatureAttribute) readInfo(reader *ClassReader) {
	c.signatureIndex = reader.readUint16()
}

func (c *SignatureAttribute) Signature() string {
	return c.cp.GetUtf8(c.signatureIndex)
}
