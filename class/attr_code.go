package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrCode attribute of Method
// https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.3
type AttrCode struct {
	*AttributeBase

	// Maximum depth of the operand stack of this method at any point during execution of the method.
	MaxStack uint16

	// The number of local variables in the local variable array allocated upon invocation of this method,
	//   including the local variables used to pass parameters to the method on its invocation.
	MaxLocals uint16

	// Actual bytes of Java Virtual Machine code that implement the method
	// If the method is either native or abstract, and is not a class or interface initialization method,
	//   then its Method structure must not have a Code attribute in its attributes table.
	//   Otherwise, its Method structure must have exactly one Code attribute in its attributes table.
	Code []byte

	// Each entry in the ExceptionTable array describes one exception handler in the code array.
	//   The order of the handlers in the ExceptionTable array is significant
	ExceptionTable []*Exception

	// Attributes related to AttrCode
	Attributes []Attribute
}

type Exception struct {
	// The values of the two items StartPC and EndPC indicate the ranges
	//    in the code array at which the exception handler is active.
	StartPC uint16
	EndPC   uint16

	// The value of the HandlerPC item indicates the start of the exception handler.
	HandlerPC uint16

	// If the value of the CatchType item is nonzero, it must be a valid index into the constant pool table.
	// If the value of the CatchType item is zero, this exception handler is called for all exceptions.
	CatchType uint16
}

func (a *AttrCode) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(8)
	if err != nil {
		return fmt.Errorf("read AttrCode attribute failed, no enough data in the stream")
	}

	a.MaxStack = binary.BigEndian.Uint16(bs[:2])
	a.MaxLocals = binary.BigEndian.Uint16(bs[2:4])
	length4 := binary.BigEndian.Uint32(bs[4:])

	a.Code, err = stream.ReadN(int(length4))
	if err != nil {
		return fmt.Errorf("read AttrCode code failed, no enough data in the stream")
	}

	bs, err = stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrCode exception length failed, no enough data in the stream")
	}

	length2 := binary.BigEndian.Uint16(bs)
	for i := uint16(0); i < length2; i++ {
		bs, err = stream.ReadN(8)
		if err != nil {
			return fmt.Errorf("read AttrCode exception failed, no enough data in the stream")
		}

		exception := &Exception{
			StartPC:   binary.BigEndian.Uint16(bs[:2]),
			EndPC:     binary.BigEndian.Uint16(bs[2:4]),
			HandlerPC: binary.BigEndian.Uint16(bs[4:6]),
			CatchType: binary.BigEndian.Uint16(bs[6:]),
		}
		a.ExceptionTable = append(a.ExceptionTable, exception)
	}

	bs, err = stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrCode attributes length failed, no enough data in the stream")
	}

	for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
		attr, err := a.class.readAttribute(stream)
		if err != nil {
			return fmt.Errorf("read AttrCode attribute failed, no enough data in the stream")
		}

		a.Attributes = append(a.Attributes, attr)
	}

	return nil
}
