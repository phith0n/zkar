package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrEnclosingMethod https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.7
type AttrEnclosingMethod struct {
	*AttributeBase

	// The value of the class_index item must be a valid index into the constant_pool table.
	ClassIndex uint16

	// The value of the method_index item must be a valid index into the constant_pool table
	MethodIndex uint16
}

func (a *AttrEnclosingMethod) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(4)
	if err != nil {
		return fmt.Errorf("read AttrEnclosingMethod failed, no enough data in the stream")
	}

	a.ClassIndex = binary.BigEndian.Uint16(bs[:2])
	a.MethodIndex = binary.BigEndian.Uint16(bs[2:])
	return nil
}
