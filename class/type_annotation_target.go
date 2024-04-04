package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// TypeParameterTarget https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.20.1
type TypeParameterTarget struct {
	TypeParameterIndex uint8
}

func NewTypeParameterTarget(stream *commons.Stream) (*TypeParameterTarget, error) {
	bs, err := stream.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("read TypeParameterTarget failed, no enough data in the stream")
	}

	return &TypeParameterTarget{TypeParameterIndex: bs[0]}, nil
}

type SuperTypeTarget struct {
	SuperTypeIndex uint16
}

func NewSuperTypeTarget(stream *commons.Stream) (*SuperTypeTarget, error) {
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read SuperTypeTarget failed, no enough data in the stream")
	}

	return &SuperTypeTarget{SuperTypeIndex: binary.BigEndian.Uint16(bs)}, nil
}

type TypeParameterBoundTarget struct {
	TypeParameterIndex uint8
	BoundIndex uint8
}

func NewTypeParameterBoundTarget(stream *commons.Stream) (*TypeParameterBoundTarget, error) {
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read TypeParameterBoundTarget failed, no enough data in the stream")
	}

	return &TypeParameterBoundTarget{TypeParameterIndex: bs[0], BoundIndex: bs[1]}, nil
}

type EmptyTarget struct {

}

type FormalParameterTarget struct {
	FormalParameterIndex uint8
}

func NewFormalParameterTarget(stream *commons.Stream) (*FormalParameterTarget, error) {
	bs, err := stream.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("read FormalParameterTarget failed, no enough data in the stream")
	}

	return &FormalParameterTarget{FormalParameterIndex: bs[0]}, nil
}

type ThrowsTarget struct {
	ThrowsTypeIndex uint16
}

func NewThrowsTarget(stream *commons.Stream) (*ThrowsTarget, error) {
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read ThrowsTarget failed, no enough data in the stream")
	}

	return &ThrowsTarget{ThrowsTypeIndex: binary.BigEndian.Uint16(bs)}, nil
}

type LocalVarTarget struct {
	Table []*LocalVarTargetTable
}

type LocalVarTargetTable struct {
	StartPC uint16
	Length uint16
	Index uint16
}

func NewLocalVarTarget(stream *commons.Stream) (*LocalVarTarget, error) {
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read LocalVarTarget failed, no enough data in the stream")
	}

	target := &LocalVarTarget{}
	for i := uint16(0); i < binary.BigEndian.Uint16(bs); i++ {
		bs, err = stream.ReadN(6)
		if err != nil {
			return nil, fmt.Errorf("read LocalVarTarget Table[%d] failed, no enough data in the stream", i)
		}

		target.Table = append(target.Table, &LocalVarTargetTable{
			StartPC: binary.BigEndian.Uint16(bs[:2]),
			Length:  binary.BigEndian.Uint16(bs[2:4]),
			Index:   binary.BigEndian.Uint16(bs[4:]),
		})
	}

	return target, nil
}

type CatchTarget struct {
	ExceptionTableIndex uint16
}

func NewCatchTarget(stream *commons.Stream) (*CatchTarget, error) {
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read CatchTarget failed, no enough data in the stream")
	}

	return &CatchTarget{ExceptionTableIndex: binary.BigEndian.Uint16(bs)}, nil
}

type OffsetTarget struct {
	Offset uint16
}

func NewOffsetTarget(stream *commons.Stream) (*OffsetTarget, error) {
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read OffsetTarget failed, no enough data in the stream")
	}

	return &OffsetTarget{Offset: binary.BigEndian.Uint16(bs)}, nil
}

type TypeArgumentTarget struct {
	Offset uint16
	TypeArgumentIndex uint8
}

func NewTypeArgumentTarget(stream *commons.Stream) (*TypeArgumentTarget, error) {
	bs, err := stream.ReadN(3)
	if err != nil {
		return nil, fmt.Errorf("read TypeArgumentTarget failed, no enough data in the stream")
	}

	return &TypeArgumentTarget{
		Offset: binary.BigEndian.Uint16(bs[:2]),
		TypeArgumentIndex: bs[2],
	}, nil
}