package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrBootstrapMethods https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.23
type AttrBootstrapMethods struct {
	*AttributeBase

	BootstrapMethods []*BootstrapMethod
}

type BootstrapMethod struct {
	// The value of the bootstrap_method_ref item must be a valid index into the constant_pool table.
	//  The constant_pool entry at that index must be a CONSTANT_MethodHandle_info structure.
	BootstrapMethodRef uint16

	// Each entry in the bootstrap_arguments array must be a valid index into the constant_pool table.
	//  The constant_pool entry at that index must be loadable.
	BoostrapArguments []uint16
}

func (a *AttrBootstrapMethods) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrBootstrapMethods failed, no enough data in the stream")
	}

	for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
		method, err := a.readBootstrapMethod(stream)
		if err != nil {
			return err
		}

		a.BootstrapMethods = append(a.BootstrapMethods, method)
	}

	return nil
}

func (a *AttrBootstrapMethods) readBootstrapMethod(stream *commons.Stream) (*BootstrapMethod, error) {
	bs, err := stream.ReadN(4)
	if err != nil {
		return nil, fmt.Errorf("read AttrBootstrapMethods BootstrapMethod failed, no enough data in the stream")
	}

	length := binary.BigEndian.Uint16(bs[2:])
	method := &BootstrapMethod{
		BootstrapMethodRef: binary.BigEndian.Uint16(bs[:2]),
	}
	for i := uint16(0); i < length; i++ {
		bs, err = stream.ReadN(2)
		if err != nil {
			return nil, fmt.Errorf("read AttrBootstrapMethods BootstrapMethod argument[%d] failed, no enough data in the stream", i)
		}

		method.BoostrapArguments = append(method.BoostrapArguments, binary.BigEndian.Uint16(bs))
	}

	return method, nil
}
