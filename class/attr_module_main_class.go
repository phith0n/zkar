package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrModuleMainClass https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.27
type AttrModuleMainClass struct {
	*AttributeBase

	MainClassIndex uint16
}

func (a *AttrModuleMainClass) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrModuleMainClass failed, no enough data in the stream")
	}

	a.MainClassIndex = binary.BigEndian.Uint16(bs)
	return nil
}
