package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type AttrModule struct {
	*AttributeBase

	ModuleName         uint16
	ModuleFlags        uint16
	ModuleVersionIndex uint16

	Requires  []*ModuleRequires
	Exports   []*ModuleExports
	Opens     []*ModuleOpens
	UsesIndex []uint16
	Provides  []*ModuleProvides
}

func (a *AttrModule) readInfo(stream *commons.Stream) error {
	bs, err := stream.ReadN(6)
	if err != nil {
		return fmt.Errorf("read AttrModule failed, no enough data in the stream")
	}

	a.ModuleName = binary.BigEndian.Uint16(bs[:2])
	a.ModuleFlags = binary.BigEndian.Uint16(bs[2:4])
	a.ModuleVersionIndex = binary.BigEndian.Uint16(bs[4:])
	return nil
}

type ModuleRequires struct {
	RequiresIndex        uint16
	RequiresFlags        uint16
	RequiresVersionIndex uint16
}

func (a *AttrModule) readRequires(stream *commons.Stream) ([]*ModuleRequires, error) {
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read AttrModule Requires failed, no enough data in the stream")
	}

	var requires []*ModuleRequires
	length := binary.BigEndian.Uint16(bs)
	for i := uint16(0); i < length; i++ {
		bs, err = stream.ReadN(6)
		if err != nil {
			return nil, fmt.Errorf("read AttrModule Requires[%d] failed, no enough data in the stream", i)
		}

		requires = append(requires, &ModuleRequires{
			RequiresIndex:        binary.BigEndian.Uint16(bs[:2]),
			RequiresFlags:        binary.BigEndian.Uint16(bs[2:4]),
			RequiresVersionIndex: binary.BigEndian.Uint16(bs[4:]),
		})
	}
	return requires, nil
}

type ModuleExports struct {
	ExportsIndex   uint16
	ExportsFlags   uint16
	ExportsToIndex []uint16
}

func (a *AttrModule) readExports(stream *commons.Stream) ([]*ModuleExports, error) {
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read AttrModule Exports failed, no enough data in the stream")
	}

	var exports []*ModuleExports
	length := binary.BigEndian.Uint16(bs)
	for i := uint16(0); i < length; i++ {
		bs, err = stream.ReadN(6)
		if err != nil {
			return nil, fmt.Errorf("read AttrModule Exports[%d] failed, no enough data in the stream", i)
		}

		export := &ModuleExports{
			ExportsIndex: binary.BigEndian.Uint16(bs[:2]),
			ExportsFlags: binary.BigEndian.Uint16(bs[2:4]),
		}

		for j := uint16(0); j < binary.BigEndian.Uint16(bs[4:]); j++ {
			data, err := stream.ReadN(2)
			if err != nil {
				return nil, fmt.Errorf("read AttrModule Exports[%d] ExportsToIndex[%d] failed, no enough data in the stream", i, j)
			}

			export.ExportsToIndex = append(export.ExportsToIndex, binary.BigEndian.Uint16(data))
		}
		exports = append(exports, export)
	}
	return exports, nil
}

type ModuleOpens struct {
	OpensIndex   uint16
	OpensFlags   uint16
	OpensToIndex []uint16
}

type ModuleProvides struct {
	ProvidesIndex     uint16
	ProvidesWithIndex []uint16
}
