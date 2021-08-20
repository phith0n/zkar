package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrSourceFile attribute of ClassFile
type AttrSourceFile struct {
	*AttributeBase
	SourceFileIndex    uint16 // indicate the name of the source file of the class
}

func (a *AttrSourceFile) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrSourceFile attribute failed, no enough data in the stream")
	}

	a.SourceFileIndex = binary.BigEndian.Uint16(bs)
	return nil
}
