package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type TCProxyClassDesc struct {
	InterfaceNames    []*TCUtf
	ClassAnnotation   []*TCContent
	SuperClassPointer *TCClassPointer
}

func (pc *TCProxyClassDesc) ToBytes() []byte {
	var bs = []byte{JAVA_TC_PROXYCLASSDESC}

	bs = append(bs, NumberToBytes(uint32(len(pc.InterfaceNames)))...)
	for _, s := range pc.InterfaceNames {
		bs = append(bs, s.ToBytes()...)
	}

	for _, content := range pc.ClassAnnotation {
		bs = append(bs, content.ToBytes()...)
	}
	bs = append(bs, JAVA_TC_ENDBLOCKDATA)
	bs = append(bs, pc.SuperClassPointer.ToBytes()...)
	return bs
}

func readTCProxyClassDesc(stream *ObjectStream) (*TCProxyClassDesc, error) {
	var desc = new(TCProxyClassDesc)

	_, _ = stream.ReadN(1)
	stream.AddReference(desc)

	bs, err := stream.ReadN(4)
	if err != nil {
		sugar.Error(err)
		return nil, fmt.Errorf("read JAVA_TC_PROXYCLASSDESC failed on index %v", stream.CurrentIndex())
	}

	size := binary.BigEndian.Uint32(bs)
	for i := uint32(0); i < size; i++ {
		str, err := readUTF(stream)
		if err != nil {
			return nil, err
		}

		desc.InterfaceNames = append(desc.InterfaceNames, str)
	}

	// classAnnotation
	desc.ClassAnnotation, err = readTCAnnotation(stream)
	if err != nil {
		return nil, err
	}

	// superClassDesc
	desc.SuperClassPointer, err = readTCClassPointer(stream)
	if err != nil {
		return nil, err
	}

	return desc, nil
}
