package class

type Exception struct {
	// The values of the two items StartPC and EndPC indicate the ranges
	//    in the code array at which the exception handler is active.
	StartPC uint16
	EndPC uint16

	// The value of the HandlerPC item indicates the start of the exception handler.
	HandlerPC uint16

	// If the value of the CatchType item is nonzero, it must be a valid index into the constant pool table.
	// If the value of the CatchType item is zero, this exception handler is called for all exceptions.
	CatchType uint16
}


