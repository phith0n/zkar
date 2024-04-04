package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrRuntimeVisibleAnnotations https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.16
type AttrRuntimeVisibleAnnotations struct {
	*AttributeBase

	Annotations []*Annotation
}

func (a *AttrRuntimeVisibleAnnotations) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrRuntimeVisibleAnnotations failed, no enough data in the stream")
	}

	for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
		annotation, err := NewAnnotation(stream)
		if err != nil {
			return fmt.Errorf("read AttrRuntimeVisibleAnnotations Annotation[%d] failed, no enough data in the stream", i)
		}

		a.Annotations = append(a.Annotations, annotation)
	}

	return nil
}
