package core

type InstructionSet struct {
	ClassName  string
	MethodName string
	Desc       string
	InstArray  []InstructionEntry
}

type InstructionEntry struct {
	Instrument string
	Operands   []string
}
