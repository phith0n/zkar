package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrExceptions https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html#jvms-4.7.5
type AttrExceptions struct {
	*AttributeBase

	// Each value in the exception_index_table array must be a valid index into the constant_pool table.
	// The constant_pool entry at that index must be a CONSTANT_Class_info structure (§4.4.1) representing
	//  a class type that this method is declared to throw.
	ExceptionIndexes []uint16
}

func (a *AttrExceptions) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrExceptions exception length failed, no enough data in the stream")
	}

	length := binary.BigEndian.Uint16(bs)
	for i := uint16(0); i < length; i++ {
		bs, err = stream.ReadN(2)
		if err != nil {
			return fmt.Errorf("read AttrExceptions exception failed, no enough data in the stream")
		}

		a.ExceptionIndexes = append(a.ExceptionIndexes, binary.BigEndian.Uint16(bs))
	}

	return nil
}
