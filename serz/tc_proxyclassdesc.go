package serz

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
	var b = newPrinter()
	b.printf("TC_PROXYCLASSDESC - %s", Hexify(JAVA_TC_PROXYCLASSDESC))
	b.increaseIndent()
	b.printf("@Handler - %v", pc.Handler)
	b.printf("@InterfaceCount - %d - %s", len(pc.InterfaceNames), Hexify(uint32(len(pc.InterfaceNames))))
	b.increaseIndent()
	for index, ifce := range pc.InterfaceNames {
		b.printf("Index %d:", index)
		b.increaseIndent()
		b.print(ifce.ToString())
		b.decreaseIndent()
	}
	b.decreaseIndent()

	b.print("@ClassAnnotations")
	b.increaseIndent()
	for index, content := range pc.ClassAnnotation {
		b.printf("Index %d", index)
		b.increaseIndent()
		b.print(content.ToString())
		b.decreaseIndent()
	}
	b.printf("TC_ENDBLOCKDATA - %s", Hexify(JAVA_TC_ENDBLOCKDATA))
	b.decreaseIndent()

	b.print("@SuperClassDesc")
	b.increaseIndent()
	b.print(pc.SuperClassPointer.ToString())
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
