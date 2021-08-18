package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

func (cf *ClassFile) readInterfaces(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read interface count failed, no enough data in the stream")
	}

	var size = binary.BigEndian.Uint16(bs)
	for i := uint16(0); i < size; i++ {
		bs, err = stream.ReadN(2)
		if err != nil {
			return fmt.Errorf("read interface array failed, no enough data in the stream")
		}

		cf.InterfaceIndexArray = append(cf.InterfaceIndexArray, binary.BigEndian.Uint16(bs))
	}

	return nil
}
