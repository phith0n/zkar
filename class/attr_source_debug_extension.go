package class

import (
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrSourceDebugExtension https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html#jvms-4.7.11
type AttrSourceDebugExtension struct {
	*AttributeBase

	// The DebugExtension array holds extended debugging information which has no semantic effect on the Java Virtual Machine.
	DebugExtension []byte
}

func (a *AttrSourceDebugExtension) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(int(a.AttributeLength))
	if err != nil {
		return fmt.Errorf("read AttrSourceDebugExtension failed, no enough data in the stream")
	}

	a.DebugExtension = bs
	return nil
}
