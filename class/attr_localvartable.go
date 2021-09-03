package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type AttrLocalVariableTable struct {
	*AttributeBase

	Tables []*LocalVariableTable
}

type LocalVariableTable struct {
	StartPC uint16
	Length uint16
	NameIndex uint16
	DescriptorIndex uint16
	Index uint16
}

func (a *AttrLocalVariableTable) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrLocalVariableTable failed, no enough data in the stream")
	}

	for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
		bs, err = stream.ReadN(10)
		if err != nil {
			return fmt.Errorf("read AttrLocalVariableTable tables failed, no enough data in the stream")
		}

		table := &LocalVariableTable{
			StartPC: binary.BigEndian.Uint16(bs[:2]),
			Length: binary.BigEndian.Uint16(bs[2:4]),
			NameIndex: binary.BigEndian.Uint16(bs[4:6]),
			DescriptorIndex: binary.BigEndian.Uint16(bs[6:8]),
			Index: binary.BigEndian.Uint16(bs[8:]),
		}
		a.Tables = append(a.Tables, table)
	}

	return nil
}
