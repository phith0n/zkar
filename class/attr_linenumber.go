package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrLineNumberTable https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html#jvms-4.7.12
type AttrLineNumberTable struct {
	*AttributeBase

	Tables []*LineNumberTable
}

type LineNumberTable struct {
	// The value of the StartPC item must be a valid index into the code array of this AttrCode attribute.
	StartPC uint16

	// The value of the LineNumber item gives the corresponding line number in the original source file.
	LineNumber uint16
}

func (a *AttrLineNumberTable) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrLineNumberTable failed, no enough data in the stream")
	}

	for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
		bs, err = stream.ReadN(4)
		if err != nil {
			return fmt.Errorf("read AttrLineNumberTable line numbers failed, no enough data in the stream")
		}

		table := &LineNumberTable{
			StartPC: binary.BigEndian.Uint16(bs[:2]),
			LineNumber: binary.BigEndian.Uint16(bs[2:]),
		}
		a.Tables = append(a.Tables, table)
	}

	return nil
}
