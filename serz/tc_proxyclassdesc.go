package serz

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type TCProxyClassDesc struct {
	InterfaceNames    []*TCUtf
	ClassAnnotation   []*TCContent
	SuperClassPointer *TCClassPointer
	Handler uint32
}

func (pc *TCProxyClassDesc) ToBytes() []byte {
	var bs = []byte{JAVA_TC_PROXYCLASSDESC}

	bs = append(bs, commons.NumberToBytes(uint32(len(pc.InterfaceNames)))...)
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
	var b = commons.NewPrinter()
	b.Printf("TC_PROXYCLASSDESC - %s", commons.Hexify(JAVA_TC_PROXYCLASSDESC))
	b.IncreaseIndent()
	b.Printf("@Handler - %v", pc.Handler)
	b.Printf("@InterfaceCount - %d - %s", len(pc.InterfaceNames), commons.Hexify(uint32(len(pc.InterfaceNames))))
	b.IncreaseIndent()
	for index, ifce := range pc.InterfaceNames {
		b.Printf("Index %d:", index)
		b.IncreaseIndent()
		b.Print(ifce.ToString())
		b.DecreaseIndent()
	}
	b.DecreaseIndent()

	b.Print("@ClassAnnotations")
	b.IncreaseIndent()
	for index, content := range pc.ClassAnnotation {
		b.Printf("Index %d", index)
		b.IncreaseIndent()
		b.Print(content.ToString())
		b.DecreaseIndent()
	}
	b.Printf("TC_ENDBLOCKDATA - %s", commons.Hexify(JAVA_TC_ENDBLOCKDATA))
	b.DecreaseIndent()

	b.Print("@SuperClassDesc")
	b.IncreaseIndent()
	b.Print(pc.SuperClassPointer.ToString())
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
