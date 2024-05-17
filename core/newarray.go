package core

/*
T_BOOLEAN	4
T_CHAR		5
T_FLOAT		6
T_DOUBLE	7
T_BYTE		8
T_SHORT		9
T_INT		10
T_LONG		11
*/

type NEWARRAY struct {
	arrayType uint8
}

func (self *NEWARRAY) FetchOperands(reader *BytecodeReader) {
	self.arrayType = reader.ReadUint8()
}

func (self *NEWARRAY) GetOperands() []string {
	ret := make([]string, 1)
	ret[0] = string(self.arrayType)
	return ret
}
