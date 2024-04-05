package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrPermittedSubclasses https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.31
type AttrPermittedSubclasses struct {
	*AttributeBase

	// Each value in the classes array must be a valid index into the constant_pool table.
	//  The constant_pool entry at that index must be a CONSTANT_Class_info structure (§4.4.1) representing a class or interface which is authorized to directly extend or implement the current class or interface.
	classes []uint16
}

func (a *AttrPermittedSubclasses) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrPermittedSubclasses failed, no enough data in the stream")
	}

	length := binary.BigEndian.Uint16(bs)
	for i := uint16(0); i < length; i++ {
		bs, err = stream.ReadN(2)
		if err != nil {
			return fmt.Errorf("read AttrPermittedSubclasses class[%d] failed, no enough data in the stream", i)
		}

		a.classes = append(a.classes, binary.BigEndian.Uint16(bs))
	}

	return nil
}
