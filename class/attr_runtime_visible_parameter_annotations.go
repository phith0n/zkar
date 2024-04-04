package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type AttrRuntimeVisibleParameterAnnotations struct {
	*AttributeBase

	Parameters []*ParameterAnnotation
}

type ParameterAnnotation struct {
	Annotations []*Annotation
}

func (a *AttrRuntimeVisibleParameterAnnotations) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(1)
	if err != nil {
		return fmt.Errorf("read Annotation failed, no enough data in the stream")
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

func (a *AttrRuntimeVisibleParameterAnnotations) readParameter(stream *commons.Stream) (*ParameterAnnotation, error) {
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read ParameterAnnotation failed, no enough data in the stream")
	}

	parameter := &ParameterAnnotation{}
	for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
		annotation, err := NewAnnotation(stream)
		if err != nil {
			return nil, fmt.Errorf("read ParameterAnnotation failed, caused by: %v", err)
		}

		parameter.Annotations = append(parameter.Annotations, annotation)
	}

	return parameter, nil
}
