package core

type JSR struct{ Index16Instruction }

type JSR_W struct {
}

func (J JSR_W) FetchOperands(reader *BytecodeReader) {
	reader.ReadUint8()
	reader.ReadUint8()
	reader.ReadUint8()
	reader.ReadUint8()
}

func (self *JSR_W) GetOperands() []string {
	ret := make([]string, 1)
	ret[0] = "[not support]"
	return ret
}
