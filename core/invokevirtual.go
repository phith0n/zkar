package core

import (
	"fmt"
	"reflect"

	"github.com/phith0n/zkar/classfile"
	"github.com/phith0n/zkar/global"
)

type INVOKEVIRTUAL struct{ Index16Instruction }

func (self *INVOKEVIRTUAL) GetOperands() []string {
	name := global.CP.GetConstantInfo(uint16(self.Index))
	typeName := reflect.TypeOf(name).String()

	var (
		className  string
		methodName string
		desc       string
	)

	switch typeName {
	case InterfaceMethodType:
		className = name.(*classfile.ConstantInterfaceMethodRefInfo).ClassName()
		methodName, desc = name.(*classfile.ConstantInterfaceMethodRefInfo).NameAndDescriptor()
	case MethodType:
		className = name.(*classfile.ConstantMethodRefInfo).ClassName()
		methodName, desc = name.(*classfile.ConstantMethodRefInfo).NameAndDescriptor()
	default:
		panic("error")
	}

	ret := make([]string, 1)
	out := fmt.Sprintf("%s.%s %s", className, methodName, desc)
	ret[0] = out
	return ret
}
