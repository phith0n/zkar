package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrInnerClass https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html#jvms-4.7.6
type AttrInnerClass struct {
	*AttributeBase

	InnerClasses []*InnerClass
}

type InnerClass struct {
	// The value of the InnerClassInfo item must be a valid index into the constant_pool table.
	InnerClassInfo uint16

	// The value of the InnerClassIndex item must be a valid index into the constant_pool table
	OuterClassInfo uint16

	// The value of the InnerClassIndex item must be a valid index into the constant_pool table
	InnerClassIndex uint16

	// The value of the InnerClassAccessFlags item is a mask of flags used to denote access permissions to
	//  and properties of class or interface C as declared in the source code from which this class file was compiled.
	InnerClassAccessFlags uint16
}

func (a *AttrInnerClass) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrInnerClass failed, no enough data in the stream")
	}

	for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
		c, err := a.readInnerClass(stream)
		if err != nil {
			return err
		}

		a.InnerClasses = append(a.InnerClasses, c)
	}

	return nil
}

func (a *AttrInnerClass) readInnerClass(stream *commons.Stream) (*InnerClass, error) {
	bs, err := stream.ReadN(8)
	if err != nil {
		return nil, fmt.Errorf("read AttrInnerClass InnerClass failed, no enough data in the stream")
	}

	c := &InnerClass{
		InnerClassInfo: binary.BigEndian.Uint16(bs[:2]),
		OuterClassInfo: binary.BigEndian.Uint16(bs[2:4]),
		InnerClassIndex: binary.BigEndian.Uint16(bs[4:6]),
		InnerClassAccessFlags: binary.BigEndian.Uint16(bs[6:]),
	}
	return c, nil
}

func (ic *InnerClass) HasFlag(flag uint16) bool {
	return (flag & ic.InnerClassAccessFlags) == flag
}
