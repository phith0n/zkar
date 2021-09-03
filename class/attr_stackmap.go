package class

import (
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// The AttrStackMapTable attribute is a variable-length attribute in the attributes table of a Code attribute.
// A AttrStackMapTable attribute is used during the process of verification by type checking.
type AttrStackMapTable struct {
	*AttributeBase

	Data []byte
}

// readInfo not implement
// TODO: read detail information of AttrStackMapTable
func (a *AttrStackMapTable) readInfo(stream *commons.Stream) error {
	var err error
	a.Data, err = stream.ReadN(int(a.AttributeLength))
	if err != nil {
		return fmt.Errorf("read AttrStackMapTable failed, no enough data in the stream")
	}

	return nil
}
