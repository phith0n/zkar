package core

type INVOKEDYNAMIC struct {
}

func (self INVOKEDYNAMIC) FetchOperands(reader *BytecodeReader) {
	reader.ReadInt8()
	reader.ReadInt8()
	reader.ReadInt8()
	reader.ReadInt8()
}

func (self *INVOKEDYNAMIC) GetOperands() []string {
	ret := make([]string, 1)
	ret[0] = NotSupport
	return ret
}
