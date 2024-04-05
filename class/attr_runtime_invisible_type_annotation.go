package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrRuntimeInvisibleTypeAnnotations https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.21
type AttrRuntimeInvisibleTypeAnnotations struct {
	*AttributeBase

	Annotations []*TypeAnnotation
}

func (a *AttrRuntimeInvisibleTypeAnnotations) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrRuntimeInvisibleTypeAnnotations failed, no enough data in the stream")
	}

	for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
		var annotation *TypeAnnotation
		annotation, err = NewTypeAnnotation(stream)
		if err != nil {
			return fmt.Errorf("read AttrRuntimeInvisibleTypeAnnotations TypeAnnotation[%d] failed, caused by: %v", i, err)
		}

		a.Annotations = append(a.Annotations, annotation)
	}

	return nil
}
