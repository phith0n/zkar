package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

const (
	ACC_PUBLIC uint16 = 0x0001 // Declared public; may be accessed from outside its package.
	ACC_FINAL uint16 = 0x0010 // Declared final; no subclasses allowed.
	ACC_SUPER uint16 = 0x0020 // Treat superclass methods specially when invoked by the invokespecial instruction.
	ACC_INTERFACE uint16 = 0x0200 // Is an interface, not a class.
	ACC_ABSTRACT uint16 = 0x0400 // Declared abstract; must not be instantiated.
	ACC_SYNTHETIC uint16 = 0x1000 // Declared synthetic; not present in the source code.
	ACC_ANNOTATION uint16 = 0x2000 // Declared as an annotation type.
	ACC_ENUM uint16 = 0x4000 // Declared as an enum type.
	ACC_MODULE uint16 = 0x8000 // Is a module, not a class or interface.
)

func (cf *ClassFile) HasAccessFlag(flag uint16) bool {
	return (flag & cf.AccessFlag) == flag
}

func (cf *ClassFile) readAccessFlag(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read access flag failed, no enough data in the stream")
	}

	var i = binary.BigEndian.Uint16(bs)
	cf.AccessFlag = i

	// check access flag valid
	if cf.HasAccessFlag(ACC_FINAL) && cf.HasAccessFlag(ACC_ABSTRACT) {
		return fmt.Errorf("ACC_FINAL and ACC_ABSTRACT are not able to set at the same time")
	}

	if cf.HasAccessFlag(ACC_ANNOTATION) && !cf.HasAccessFlag(ACC_ANNOTATION) {
		return fmt.Errorf("if ACC_ANNOTATION is set, ACC_ANNOTATION must also be set")
	}

	// TODO: more check

	return nil
}
