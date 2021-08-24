package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrSignature https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html#jvms-4.7.9
type AttrSignature struct {
	*AttributeBase

	// The value of the SignatureIndex item must be a valid index into the constant_pool table.
	SignatureIndex uint16
}

func (a *AttrSignature) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrSignature failed, no enough data in the stream")
	}

	a.SignatureIndex = binary.BigEndian.Uint16(bs)
	return nil
}
