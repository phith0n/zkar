package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrLocalVariableTypeTable https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.14
type AttrLocalVariableTypeTable struct {
	*AttributeBase

	Tables []*LocalVariableTypeTable
}

type LocalVariableTypeTable struct {
	StartPC        uint16
	Length         uint16
	NameIndex      uint16
	SignatureIndex uint16
	Index          uint16
}

func (a *AttrLocalVariableTypeTable) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrLocalVariableTypeTable failed, no enough data in the stream")
	}

	length := binary.BigEndian.Uint16(bs)
	for i := uint16(0); i < length; i++ {
		bs, err = stream.ReadN(10)
		if err != nil {
			return fmt.Errorf("read AttrLocalVariableTypeTable tables failed, no enough data in the stream")
		}

		table := &LocalVariableTypeTable{
			StartPC:        binary.BigEndian.Uint16(bs[:2]),
			Length:         binary.BigEndian.Uint16(bs[2:4]),
			NameIndex:      binary.BigEndian.Uint16(bs[4:6]),
			SignatureIndex: binary.BigEndian.Uint16(bs[6:8]),
			Index:          binary.BigEndian.Uint16(bs[8:]),
		}
		a.Tables = append(a.Tables, table)
	}

	return nil
}
