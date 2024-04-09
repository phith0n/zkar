package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrModulePackages https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.26
type AttrModulePackages struct {
	*AttributeBase

	PackageIndex []uint16
}

func (a *AttrModulePackages) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrModulePackages failed, no enough data in the stream")
	}

	length := binary.BigEndian.Uint16(bs)
	for i := uint16(0); i < length; i++ {
		bs, err = stream.ReadN(2)
		if err != nil {
			return fmt.Errorf("read AttrModulePackages[%d] failed, no enough data in the stream", i)
		}

		a.PackageIndex = append(a.PackageIndex, binary.BigEndian.Uint16(bs))
	}

	return nil
}
