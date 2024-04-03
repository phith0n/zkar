package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrConstValue attribute of Field
// https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.2
type AttrConstValue struct {
	*AttributeBase

	// indicate the index of the constant value
	// one of ConstantInteger, ConstantFloat, ConstantDouble, ConstantString, ConstantLong
	ConstantValueIndex uint16
}

func (a *AttrConstValue) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrSourceFile attribute failed, no enough data in the stream")
	}

	a.ConstantValueIndex = binary.BigEndian.Uint16(bs)
	return nil
}
