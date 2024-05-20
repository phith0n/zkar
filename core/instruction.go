package core

import (
	"strconv"
)

type Instruction interface {
	FetchOperands(reader *BytecodeReader)
	GetOperands() []string
}

type NoOperandsInstruction struct {
}

func (self *NoOperandsInstruction) FetchOperands(_ *BytecodeReader) {
}

func (self *NoOperandsInstruction) GetOperands() []string {
	return make([]string, 0)
}

type BranchInstruction struct {
	Offset int
}

func (self *BranchInstruction) FetchOperands(reader *BytecodeReader) {
	self.Offset = int(reader.ReadInt16())
}

func (self *BranchInstruction) GetOperands() []string {
	ret := make([]string, 1)
	ret[0] = strconv.Itoa(self.Offset)
	return ret
}

type Index8Instruction struct {
	Index uint
}

func (self *Index8Instruction) FetchOperands(reader *BytecodeReader) {
	self.Index = uint(reader.ReadUint8())
}

func (self *Index8Instruction) GetOperands() []string {
	ret := make([]string, 1)
	ret[0] = strconv.Itoa(int(self.Index))
	return ret
}

type Index16Instruction struct {
	Index uint
}

func (self *Index16Instruction) FetchOperands(reader *BytecodeReader) {
	self.Index = uint(reader.ReadUint16())
}

func (self *Index16Instruction) GetOperands() []string {
	ret := make([]string, 1)
	ret[0] = strconv.Itoa(int(self.Index))
	return ret
}
