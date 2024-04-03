package class

import "github.com/phith0n/zkar/commons"

// AttrSynthetic https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.8
type AttrSynthetic struct {
	*AttributeBase
}

func (a *AttrSynthetic) readInfo(stream *commons.Stream) error {
	// read nothing
	return nil
}
