package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type TCProxyClassDesc struct {
	InterfaceNames    []*TCUtf
	ClassAnnotation   []*TCContent
	SuperClassPointer *TCClassPointer
	Handler uint32
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

func (pc *TCProxyClassDesc) ToString() string {
	var b = NewPrinter()
	b.Printf("TC_PROXYCLASSDESC - %s\n", Hexify(JAVA_TC_PROXYCLASSDESC))
	b.IncreaseIndent()
	b.Printf("@Handler - %v\n", pc.Handler)
	b.Printf("@InterfaceCount - %d - %s\n", len(pc.InterfaceNames), Hexify(uint32(len(pc.InterfaceNames))))
	b.IncreaseIndent()
	for index, ifce := range pc.InterfaceNames {
		b.Printf("Index %d:\n", index)
		b.IncreaseIndent()
		b.Printf(ifce.ToString())
		b.DecreaseIndent()
	}
	b.DecreaseIndent()

	b.Printf("@ClassAnnotations \n")
	b.IncreaseIndent()
	for index, content := range pc.ClassAnnotation {
		b.Printf("Index %d\n", index)
		b.IncreaseIndent()
		b.Printf(content.ToString())
		b.DecreaseIndent()
		b.Printf("\n")
	}
	b.Printf("TC_ENDBLOCKDATA - %s\n", Hexify(JAVA_TC_ENDBLOCKDATA))
	b.DecreaseIndent()

	b.Printf("@SuperClassDesc \n")
	b.IncreaseIndent()
	b.Printf(pc.SuperClassPointer.ToString())
	return b.String()
}

func readTCProxyClassDesc(stream *ObjectStream) (*TCProxyClassDesc, error) {
	var desc = new(TCProxyClassDesc)

	_, _ = stream.ReadN(1)
	stream.AddReference(desc)

	bs, err := stream.ReadN(4)
	if err != nil {
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
