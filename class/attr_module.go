package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// AttrModule https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.25
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

	a.Requires, err = a.readRequires(stream)
	if err != nil {
		return err
	}

	a.Exports, err = a.readExports(stream)
	if err != nil {
		return err
	}

	a.Opens, err = a.readOpens(stream)
	if err != nil {
		return err
	}

	bs, err = stream.ReadN(2)
	if err != nil {
		return fmt.Errorf("read AttrModule UsesIndex failed, no enough data in the stream")
	}

	for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
		data, err := stream.ReadN(2)
		if err != nil {
			return fmt.Errorf("read AttrModule UsesIndex[%d] failed, no enough data in the stream", i)
		}

		a.UsesIndex = append(a.UsesIndex, binary.BigEndian.Uint16(data))
	}

	a.Provides, err = a.readProvides(stream)
	if err != nil {
		return err
	}

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

func (a *AttrModule) readOpens(stream *commons.Stream) ([]*ModuleOpens, error) {
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read AttrModule Opens failed, no enough data in the stream")
	}

	var opens []*ModuleOpens
	length := binary.BigEndian.Uint16(bs)
	for i := uint16(0); i < length; i++ {
		bs, err = stream.ReadN(6)
		if err != nil {
			return nil, fmt.Errorf("read AttrModule Opens[%d] failed, no enough data in the stream", i)
		}

		open := &ModuleOpens{
			OpensIndex: binary.BigEndian.Uint16(bs[:2]),
			OpensFlags: binary.BigEndian.Uint16(bs[2:4]),
		}
		for j := uint16(0); j < binary.BigEndian.Uint16(bs[4:]); j++ {
			data, err := stream.ReadN(2)
			if err != nil {
				return nil, fmt.Errorf("read AttrModule Opens[%d] OpensToIndex[%d] failed, no enough data in the stream", i, j)
			}

			open.OpensToIndex = append(open.OpensToIndex, binary.BigEndian.Uint16(data))
		}
		opens = append(opens, open)
	}

	return opens, nil
}

type ModuleProvides struct {
	ProvidesIndex     uint16
	ProvidesWithIndex []uint16
}

func (a *AttrModule) readProvides(stream *commons.Stream) ([]*ModuleProvides, error) {
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read AttrModule Provides failed, no enough data in the stream")
	}

	var provides []*ModuleProvides
	length := binary.BigEndian.Uint16(bs)
	for i := uint16(0); i < length; i++ {
		bs, err = stream.ReadN(4)
		if err != nil {
			return nil, fmt.Errorf("read AttrModule Provides[%d] failed, no enough data in the stream", i)
		}

		provide := &ModuleProvides{
			ProvidesIndex: binary.BigEndian.Uint16(bs[:2]),
		}

		for j := uint16(0); j < binary.BigEndian.Uint16(bs[2:]); j++ {
			data, err := stream.ReadN(2)
			if err != nil {
				return nil, fmt.Errorf("read AttrModule Opens[%d] OpensToIndex[%d] failed, no enough data in the stream", i, j)
			}

			provide.ProvidesWithIndex = append(provide.ProvidesWithIndex, binary.BigEndian.Uint16(data))
		}
		provides = append(provides, provide)
	}
	return provides, nil
}
