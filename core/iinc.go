package core

import "strconv"

type IINC struct {
	Index uint
	Const int32
}

func (self *IINC) FetchOperands(reader *BytecodeReader) {
	self.Index = uint(reader.ReadUint8())
	self.Const = int32(reader.ReadInt8())
}

func (self *IINC) GetOperands() []string {
	ret := make([]string, 2)
	ret[0] = strconv.Itoa(int(self.Index))
	ret[1] = strconv.Itoa(int(self.Const))
	return ret
}
