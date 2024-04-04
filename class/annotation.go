package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type Annotation struct {
	TypeIndex uint16
	ElementValuePairs []*ElementValuePair
}

type ElementValuePair struct {
	ElementNameIndex uint16
	ElementValue     *ElementValue
}

func NewAnnotation(stream *commons.Stream) (*Annotation, error) {
	bs, err := stream.ReadN(4)
	if err != nil {
		return nil, fmt.Errorf("read Annotation failed, no enough data in the stream")
	}

	a := &Annotation{
		TypeIndex: binary.BigEndian.Uint16(bs[:2]),
	}

	for i := uint16(0); i < binary.BigEndian.Uint16(bs[2:]); i++ {
		bs, err = stream.ReadN(2)
		if err != nil {
			return nil, fmt.Errorf("read Annotation ElementValuePair[%d] failed, no enough data in the stream", i)
		}

		pair := &ElementValuePair{
			ElementNameIndex: binary.BigEndian.Uint16(bs),
		}
		pair.ElementValue, err = NewElementValue(stream)
		if err != nil {
			return nil, fmt.Errorf("read Annotation ElementValuePair[%d] failed, caused by: %v", i, err)
		}

		a.ElementValuePairs = append(a.ElementValuePairs, pair)
	}

	return a, nil
}
