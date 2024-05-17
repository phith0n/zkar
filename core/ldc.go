package core

import (
	"reflect"

	"github.com/phith0n/zkar/classfile"
	"github.com/phith0n/zkar/global"
)

type LDC struct{ Index8Instruction }

func (self *LDC) GetOperands() []string {
	name := global.CP.GetConstantInfo(uint16(self.Index))
	typeName := reflect.TypeOf(name).String()

	var constString string

	switch typeName {
	case "*classfile.ConstantStringInfo":
		constString = name.(*classfile.ConstantStringInfo).String()
	default:
		panic("error")
	}

	ret := make([]string, 1)
	out := constString
	ret[0] = out
	return ret
}

type LDC_W struct{ Index16Instruction }

type LDC2_W struct{ Index16Instruction }
