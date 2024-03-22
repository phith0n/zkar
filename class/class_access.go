package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ClassAccessFlag uint16

const (
	ClassAccPublic     ClassAccessFlag = 0x0001 // Declared public; may be accessed from outside its package.
	ClassAccPrivate    ClassAccessFlag = 0x0002 // Marked private in source.
	ClassAccProtected  ClassAccessFlag = 0x0004 // Marked protected in source.
	ClassAccStatic     ClassAccessFlag = 0x0008 // Marked or implicitly static in source.
	ClassAccFinal      ClassAccessFlag = 0x0010 // Declared final; no subclasses allowed.
	ClassAccSuper      ClassAccessFlag = 0x0020 // Treat superclass methods specially when invoked by the invokespecial instruction.
	ClassAccInterface  ClassAccessFlag = 0x0200 // Is an interface, not a class.
	ClassAccAbstract   ClassAccessFlag = 0x0400 // Declared abstract; must not be instantiated.
	ClassAccSynthetic  ClassAccessFlag = 0x1000 // Declared synthetic; not present in the source code.
	ClassAccAnnotation ClassAccessFlag = 0x2000 // Declared as an annotation type.
	ClassAccEnum       ClassAccessFlag = 0x4000 // Declared as an enum type.
	ClassAccModule     ClassAccessFlag = 0x8000 // Is a module, not a class or interface.
)

func (caf ClassAccessFlag) HasAccessFlag(flag ClassAccessFlag) bool {
	return (flag & caf) == flag
}

func (cf *ClassFile) readAccessFlag(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read access flag failed, no enough data in the stream")
	}

	var i = binary.BigEndian.Uint16(bs)
	cf.AccessFlag = ClassAccessFlag(i)

	// check access flag valid
	if cf.AccessFlag.HasAccessFlag(ClassAccFinal) && cf.AccessFlag.HasAccessFlag(ClassAccAbstract) {
		return fmt.Errorf("ACC_FINAL and ACC_ABSTRACT are not able to set at the same time")
	}

	if cf.AccessFlag.HasAccessFlag(ClassAccAnnotation) && !cf.AccessFlag.HasAccessFlag(ClassAccInterface) {
		return fmt.Errorf("if ACC_ANNOTATION is set, ACC_ANNOTATION must also be set")
	}

	// TODO: maybe need more check
	return nil
}
