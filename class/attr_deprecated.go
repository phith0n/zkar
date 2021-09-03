package class

import "github.com/phith0n/zkar/commons"

// AttrDeprecated https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html#jvms-4.7.15
type AttrDeprecated struct {
	*AttributeBase
}

func (a *AttrDeprecated) readInfo(stream *commons.Stream) error {
	return nil
}
