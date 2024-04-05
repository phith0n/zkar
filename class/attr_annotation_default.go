package class

import (
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type AttrAnnotationDefault struct {
	*AttributeBase

	DefaultValue *ElementValue
}

func (a *AttrAnnotationDefault) readInfo(stream *commons.Stream) error {
	value, err := NewElementValue(stream)
	if err != nil {
		return fmt.Errorf("read AttrAnnotationDefault failed, caused by: %v", err)
	}

	a.DefaultValue = value
	return nil
}
