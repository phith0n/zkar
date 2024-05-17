package core

import "strconv"

type BIPUSH struct {
	val int8
}

func (self *BIPUSH) FetchOperands(reader *BytecodeReader) {
	self.val = reader.ReadInt8()
}

func (self *BIPUSH) GetOperands() []string {
	ret := make([]string, 1)
	ret[0] = strconv.Itoa(int(self.val))
	return ret
}

type SIPUSH struct {
	val int16
}

func (self *SIPUSH) FetchOperands(reader *BytecodeReader) {
	self.val = reader.ReadInt16()
}

func (self *SIPUSH) GetOperands() []string {
	ret := make([]string, 1)
	ret[0] = strconv.Itoa(int(self.val))
	return ret
}
