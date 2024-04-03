package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrRecord https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.3
type AttrRecord struct {
	*AttributeBase

	Components []*RecordComponentInfo
}

type RecordComponentInfo struct {
	// The value of the name_index item must be a valid index into the constant_pool table.
	//  The constant_pool entry at that index must be a CONSTANT_Utf8_info structure (§4.4.7) representing a valid unqualified name denoting the record component (§4.2.2).
	NameIndex uint16

	// The value of the descriptor_index item must be a valid index into the constant_pool table.
	//  The constant_pool entry at that index must be a CONSTANT_Utf8_info structure (§4.4.7) representing a field descriptor which encodes the type of the record component (§4.3.2).
	DescriptorIndex uint16

	// Each value of the attributes table must be an attribute_info structure (§4.7).
	Attributes []Attribute
}

func (a *AttrRecord) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrRecord failed, no enough data in the stream")
	}

	for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
		component, err := a.readComponent(stream)
		if err != nil {
			return err
		}

		a.Components = append(a.Components, component)
	}

	return nil
}

func (a *AttrRecord) readComponent(stream *commons.Stream) (*RecordComponentInfo, error) {
	bs, err := stream.ReadN(4)
	if err != nil {
		return nil, fmt.Errorf("read AttrRecord Component[%d] failed, no enough data in the stream", i)
	}

	component := &RecordComponentInfo{
		NameIndex:       binary.BigEndian.Uint16(bs[:2]),
		DescriptorIndex: binary.BigEndian.Uint16(bs[2:]),
	}

	attr, err := a.class.readAttribute(stream)
	if err != nil {
		return nil, fmt.Errorf("read AttrCode attribute failed, no enough data in the stream")
	}

	component.Attributes = append(component.Attributes, attr)
	return component, nil
}
