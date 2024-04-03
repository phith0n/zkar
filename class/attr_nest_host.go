package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrNestHost https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.28
type AttrNestHost struct {
	*AttributeBase

	// The value of the host_class_index item must be a valid index into the constant_pool table.
	//  The constant_pool entry at that index must be a CONSTANT_Class_info structure (§4.4.1) representing a class or interface which is the nest host for the current class or interface.
	HostClassIndex uint16
}

func (a *AttrNestHost) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrNestHost failed, no enough data in the stream")
	}

	a.HostClassIndex = binary.BigEndian.Uint16(bs)
	return nil
}
