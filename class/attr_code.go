package class

import "github.com/phith0n/zkar/commons"

// AttrCode attribute of Method
type AttrCode struct {
	*AttributeBase

	// Maximum depth of the operand stack of this method at any point during execution of the method.
	MaxStack             uint16

	// The number of local variables in the local variable array allocated upon invocation of this method,
	//   including the local variables used to pass parameters to the method on its invocation.
	MaxLocals            uint16

	// Actual bytes of Java Virtual Machine code that implement the method
	// If the method is either native or abstract, and is not a class or interface initialization method,
	//   then its Method structure must not have a Code attribute in its attributes table.
	//   Otherwise, its Method structure must have exactly one Code attribute in its attributes table.
	Code                 []byte

	// Each entry in the ExceptionTable array describes one exception handler in the code array.
	//   The order of the handlers in the ExceptionTable array is significant
	ExceptionTable       []*Exception

	// Attributes related to AttrCode
	Attributes           []Attribute
}

func (a *AttrCode) readInfo(stream *commons.Stream) error {
	// TODO
	return nil
}
