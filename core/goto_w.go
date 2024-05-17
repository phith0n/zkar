package core

type GOTO_W struct {
	offset int
}

func (self *GOTO_W) FetchOperands(reader *BytecodeReader) {
	self.offset = int(reader.ReadInt32())
}

func (self *GOTO_W) GetOperands() []string {
	ret := make([]string, 1)
	ret[0] = "[not support]"
	return ret
}
