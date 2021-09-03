package class

import (
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrAnnotations
//   https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html#jvms-4.7.16
//   https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html#jvms-4.7.17
//   https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html#jvms-4.7.18
//   https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html#jvms-4.7.19
//   https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html#jvms-4.7.20
//   https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html#jvms-4.7.21
type AttrAnnotations struct {
	*AttributeBase

	Data []byte
}

// readInfo TODO: not implement
func (a *AttrAnnotations) readInfo(stream *commons.Stream) error {
	var err error
	a.Data, err = stream.ReadN(int(a.AttributeLength))
	if err != nil {
		return fmt.Errorf("read AttrAnnotations failed, no enough data in the stream")
	}

	return nil
}
