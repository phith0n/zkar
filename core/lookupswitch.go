package core

type LOOKUPSWITCH struct {
	defaultOffset int32
	npairs        int32
	matchOffsets  []int32
}

func (self *LOOKUPSWITCH) FetchOperands(reader *BytecodeReader) {
	reader.SkipPadding()
	self.defaultOffset = reader.ReadInt32()
	self.npairs = reader.ReadInt32()
	self.matchOffsets = reader.ReadInt32s(self.npairs * 2)
}

func (self *LOOKUPSWITCH) GetOperands() []string {
	ret := make([]string, 1)
	ret[0] = NotSupport
	return ret
}
