package core

type MULTIANEWARRAY struct {
	index      uint16
	dimensions uint8
}

func (self *MULTIANEWARRAY) FetchOperands(reader *BytecodeReader) {
	self.index = reader.ReadUint16()
	self.dimensions = reader.ReadUint8()
}

func (self *MULTIANEWARRAY) GetOperands() []string {
	ret := make([]string, 1)
	ret[0] = NotSupport
	return ret
}
