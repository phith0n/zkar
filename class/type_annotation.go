package class

import (
	"fmt"
	"github.com/phith0n/zkar/commons"
)

// TypeAnnotation https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.7.20
type TypeAnnotation struct {
	TargetType uint8
	TypeParameterTarget *TypeParameterTarget
	SuperTypeTarget *SuperTypeTarget
	TypeParameterBoundTarget *TypeParameterBoundTarget
	EmptyTarget *EmptyTarget
	FormalParameterTarget *FormalParameterTarget
	ThrowsTarget *ThrowsTarget
	LocalVarTarget *LocalVarTarget
	CatchTarget *CatchTarget
	OffsetTarget *OffsetTarget
	TypeArgumentTarget *TypeArgumentTarget

	TargetPath *TypePath

	// same as Annotation
	TypeIndex uint16
	ElementValuePairs []*ElementValuePair
}

func NewTypeAnnotation(stream *commons.Stream) (*TypeAnnotation, error) {
	bs, err := stream.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("read TypeAnnotation TargetType failed, no enough data in the stream")
	}

	ta := &TypeAnnotation{
		TargetType: bs[0],
	}
	switch ta.TargetType {
	case 0x00, 0x01:
		ta.TypeParameterTarget, err = NewTypeParameterTarget(stream)
	case 0x10:
		ta.SuperTypeTarget, err = NewSuperTypeTarget(stream)
	case 0x11, 0x12:
		ta.TypeParameterBoundTarget, err = NewTypeParameterBoundTarget(stream)
	case 0x13, 0x14, 0x15:
		ta.EmptyTarget = &EmptyTarget{}
	case 0x16:
		ta.FormalParameterTarget, err = NewFormalParameterTarget(stream)
	case 0x17:
		ta.ThrowsTarget, err = NewThrowsTarget(stream)
	case 0x40, 0x41:
		ta.LocalVarTarget, err = NewLocalVarTarget(stream)
	case 0x42:
		ta.CatchTarget, err = NewCatchTarget(stream)
	case 0x43, 0x44, 0x45, 0x46:
		ta.OffsetTarget, err = NewOffsetTarget(stream)
	case 0x47, 0x48, 0x49, 0x4A, 0x4B:
		ta.TypeArgumentTarget, err = NewTypeArgumentTarget(stream)
	default:
		return nil, fmt.Errorf("read TypeAnnotation failed, TargetType %v not found", ta.TargetType)
	}

	if err != nil {
		return nil, fmt.Errorf("read TypeAnnotation TargetInfo failed, caused by: %v", err)
	}

	ta.TargetPath, err = NewTypePath(stream)
	if err != nil {
		return nil, fmt.Errorf("read TypeAnnotation TargetPath failed, caused by: %v", err)
	}

	annotation, err := NewAnnotation(stream)
	if err != nil {
		return nil, fmt.Errorf("read TypeAnnotation Annotation failed, caused by: %v", err)
	}

	ta.TypeIndex = annotation.TypeIndex
	ta.ElementValuePairs = annotation.ElementValuePairs
	return ta, nil
}
