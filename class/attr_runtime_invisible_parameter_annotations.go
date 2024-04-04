package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrRuntimeInvisibleParameterAnnotations https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.19
type AttrRuntimeInvisibleParameterAnnotations struct {
	*AttributeBase

	Parameters []*ParameterAnnotation
}

func (a *AttrRuntimeInvisibleParameterAnnotations) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(1)
	if err != nil {
		return fmt.Errorf("read AttrRuntimeInvisibleParameterAnnotations failed, no enough data in the stream")
	}

	for i := uint8(0); i < bs[0]; i++ {
		p, err := a.readParameter(stream)
		if err != nil {
			return err
		}

		a.Parameters = append(a.Parameters, p)
	}

	return nil
}

func (a *AttrRuntimeInvisibleParameterAnnotations) readParameter(stream *commons.Stream) (*ParameterAnnotation, error) {
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read AttrRuntimeInvisibleParameterAnnotations ParameterAnnotation failed, no enough data in the stream")
	}

	parameter := &ParameterAnnotation{}
	for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
		annotation, err := NewAnnotation(stream)
		if err != nil {
			return nil, fmt.Errorf("read AttrRuntimeInvisibleParameterAnnotations ParameterAnnotation failed, caused by: %v", err)
		}

		parameter.Annotations = append(parameter.Annotations, annotation)
	}

	return parameter, nil
}
