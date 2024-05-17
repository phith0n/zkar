package classfile

import "encoding/binary"

type ClassReader struct {
	data []byte
}

// u1
func (c *ClassReader) readUint8() uint8 {
	val := c.data[0]
	c.data = c.data[1:]
	return val
}

// u2
func (c *ClassReader) readUint16() uint16 {
	val := binary.BigEndian.Uint16(c.data)
	c.data = c.data[2:]
	return val
}

// u4
func (c *ClassReader) readUint32() uint32 {
	val := binary.BigEndian.Uint32(c.data)
	c.data = c.data[4:]
	return val
}

func (c *ClassReader) readUint64() uint64 {
	val := binary.BigEndian.Uint64(c.data)
	c.data = c.data[8:]
	return val
}

// uint16 table
func (c *ClassReader) readUint16s() []uint16 {
	n := c.readUint16()
	s := make([]uint16, n)
	for i := range s {
		s[i] = c.readUint16()
	}
	return s
}

func (c *ClassReader) readBytes(n uint32) []byte {
	bytes := c.data[:n]
	c.data = c.data[n:]
	return bytes
}
