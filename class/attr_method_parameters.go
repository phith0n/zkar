package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrMethodParameters https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.24
type AttrMethodParameters struct {
	*AttributeBase

	Parameters []*MethodParameter
}

type MethodParameter struct {
	NameIndex   uint16
	AccessFlags ParameterAccessFlag
}

func (a *AttrMethodParameters) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(1)
	if err != nil {
		return fmt.Errorf("read AttrMethodParameters NameIndex failed, no enough data in the stream")
	}

	length := bs[0]
	for i := uint8(0); i < length; i++ {
		bs, err = stream.ReadN(4)
		if err != nil {
			return fmt.Errorf("read AttrMethodParameters NameIndex and AccessFlag failed, no enough data in the stream")
		}

		a.Parameters = append(a.Parameters, &MethodParameter{
			NameIndex:   binary.BigEndian.Uint16(bs[:2]),
			AccessFlags: ParameterAccessFlag(binary.BigEndian.Uint16(bs[2:])),
		})
	}
	return nil
}
