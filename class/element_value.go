package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// ElementValue https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.16.1
type ElementValue struct {
	Tag byte

	ConstValueIndex uint16
	EnumConstValue  *EnumConstValue
	ClassInfoIndex  uint16
	AnnotationValue *Annotation
	ArrayValue      []*ElementValue
}

type EnumConstValue struct {
	TypeNameIndex  uint16
	ConstNameIndex uint16
}

func NewElementValue(stream *commons.Stream) (*ElementValue, error) {
	bs, err := stream.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("read ElementValue tag failed, no enough data in the stream")
	}

	element := &ElementValue{
		Tag: bs[0],
	}

	switch element.Tag {
	case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z', 's':
		bs, err = stream.ReadN(2)
		if err != nil {
			return nil, fmt.Errorf("read ElementValue ConstValueIndex failed, no enough data in the stream")
		}

		element.ConstValueIndex = binary.BigEndian.Uint16(bs)
	case 'e':
		bs, err = stream.ReadN(4)
		if err != nil {
			return nil, fmt.Errorf("read ElementValue EnumConstValue failed, no enough data in the stream")
		}

		element.EnumConstValue = &EnumConstValue{
			TypeNameIndex:  binary.BigEndian.Uint16(bs[:2]),
			ConstNameIndex: binary.BigEndian.Uint16(bs[2:]),
		}
	case 'c':
		bs, err = stream.ReadN(2)
		if err != nil {
			return nil, fmt.Errorf("read ElementValue ClassInfoIndex failed, no enough data in the stream")
		}

		element.ClassInfoIndex = binary.BigEndian.Uint16(bs)
	case '@':
		annotation, err := NewAnnotation(stream)
		if err != nil {
			return nil, fmt.Errorf("read ElementValue AnnotationValue failed, caused by: %v", err)
		}

		element.AnnotationValue = annotation
	case '[':
		bs, err = stream.ReadN(2)
		if err != nil {
			return nil, fmt.Errorf("read ElementValue ArrayValue failed, no enough data in the stream")
		}

		for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
			subElement, err := NewElementValue(stream)
			if err != nil {
				return nil, fmt.Errorf("read ElementValue ArrayValue failed, caused by: %v", err)
			}

			element.ArrayValue = append(element.ArrayValue, subElement)
		}
	default:
		return nil, fmt.Errorf("read ElementValue tag failed, tag %v not supported", element.Tag)
	}

	return element, nil
}
