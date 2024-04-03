package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrNestMembers https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.29
type AttrNestMembers struct {
	*AttributeBase

	// Each value in the classes array must be a valid index into the constant_pool table.
	//  The constant_pool entry at that index must be a CONSTANT_Class_info structure representing a class or interface which is a member of the nest hosted by the current class or interface.
	classes []uint16
}

func (a *AttrNestMembers) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrNestMembers failed, no enough data in the stream")
	}

	for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
		bs, err = stream.ReadN(2)
		if err != nil {
			return fmt.Errorf("read AttrNestMembers class[%d] failed, no enough data in the stream", i)
		}

		a.classes = append(a.classes, binary.BigEndian.Uint16(bs))
	}

	return nil
}
