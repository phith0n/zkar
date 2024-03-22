package class

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ClassFile struct {
	MagicNumber         []byte
	MinorVersion        uint16
	MajorVersion        uint16
	ConstantPool        []Constant
	AccessFlag          ClassAccessFlag
	ThisClassIndex      uint16
	SuperClassIndex     uint16
	InterfaceIndexArray []uint16
	Fields              []*Field
	Methods             []*Method
	Attributes          []*Attribute
}

func (cf *ClassFile) readHeader(stream *commons.Stream) error {
	bs, err := stream.ReadN(4)
	if err != nil {
		return fmt.Errorf("read magic number failed, no enough data in the stream")
	}

	if !bytes.Equal(bs, []byte("\xCA\xFE\xBA\xBE")) {
		return fmt.Errorf("magic number %v is not equal to 0xCAFEBABE", hex.EncodeToString(bs))
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

func (cf *ClassFile) readClass(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read this class failed, no enough data in the stream")
	}
	cf.ThisClassIndex = binary.BigEndian.Uint16(bs)

	bs, err = stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read super class failed, no enough data in the stream")
	}
	cf.SuperClassIndex = binary.BigEndian.Uint16(bs)
	return nil
}
