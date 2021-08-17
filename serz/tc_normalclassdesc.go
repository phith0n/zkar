package serz

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
	"strings"
)

type TCClassDesc struct {
	ClassName         *TCUtf
	SerialVersionUID  int64
	ClassDescFlags    byte
	Fields            []*TCFieldDesc
	ClassAnnotation   []*TCContent
	SuperClassPointer *TCClassPointer
	Handler uint32
}

func (desc *TCClassDesc) ToBytes() []byte {
	var result = []byte{JAVA_TC_CLASSDESC}
	result = append(result, desc.ClassName.ToBytes()...)
	result = append(result, commons.NumberToBytes(desc.SerialVersionUID)...)
	result = append(result, desc.ClassDescFlags)
	result = append(result, commons.NumberToBytes(uint16(len(desc.Fields)))...)
	for _, field := range desc.Fields {
		result = append(result, field.ToBytes()...)
	}
	for _, content := range desc.ClassAnnotation {
		result = append(result, content.ToBytes()...)
	}
	result = append(result, JAVA_TC_ENDBLOCKDATA)
	result = append(result, desc.SuperClassPointer.ToBytes()...)

	return result
}

func (desc *TCClassDesc) ToString() string {
	var b = commons.NewPrinter()

	b.Printf("TC_CLASSDESC - %s", commons.Hexify(JAVA_TC_CLASSDESC))
	b.IncreaseIndent()
	b.Print("@ClassName")
	b.IncreaseIndent()
	b.Print(desc.ClassName.ToString())
	b.DecreaseIndent()
	b.Printf("@SerialVersionUID - %v - %s", desc.SerialVersionUID, commons.Hexify(desc.SerialVersionUID))
	b.Printf("@Handler - %v", desc.Handler)
	b.Printf("@ClassDescFlags - %s - %s", desc.FlagString(), commons.Hexify(desc.ClassDescFlags))
	b.Printf("@FieldCount - %d - %s", len(desc.Fields), commons.Hexify(uint16(len(desc.Fields))))
	b.Print("[]Fields")
	b.IncreaseIndent()
	for index, field := range desc.Fields {
		b.Printf("Index %d:", index)
		b.IncreaseIndent()
		b.Print(field.ToString())
		b.DecreaseIndent()
	}
	b.DecreaseIndent()
	b.Print("[]ClassAnnotations")
	b.IncreaseIndent()
	for index, content := range desc.ClassAnnotation {
		b.Printf("Index %d:", index)
		b.IncreaseIndent()
		b.Print(content.ToString())
		b.DecreaseIndent()
	}
	b.Printf("TC_ENDBLOCKDATA - %s", commons.Hexify(JAVA_TC_ENDBLOCKDATA))
	b.DecreaseIndent()
	b.Print("@SuperClassDesc")
	b.IncreaseIndent()
	b.Print(desc.SuperClassPointer.ToString())

	return b.String()
}

// HasFlag Check if a TCClassDesc object has a flag
func (desc *TCClassDesc) HasFlag(flag byte) bool {
	return (desc.ClassDescFlags & flag) == flag
}

func (desc *TCClassDesc) FlagString() string {
	var descFlags []string
	if desc.HasFlag(JAVA_SC_SERIALIZABLE) {
		descFlags = append(descFlags, "SC_SERIALIZABLE")
	}
	if desc.HasFlag(JAVA_SC_WRITE_METHOD) {
		descFlags = append(descFlags, "SC_WRITE_METHOD")
	}
	if desc.HasFlag(JAVA_SC_EXTERNALIZABLE) {
		descFlags = append(descFlags, "SC_EXTERNALIZABLE")
	}
	if desc.HasFlag(JAVA_SC_BLOCK_DATA) {
		descFlags = append(descFlags, "SC_BLOCK_DATA")
	}

	return strings.Join(descFlags, "|")
}

func readTCNormalClassDesc(stream *ObjectStream) (*TCClassDesc, error) {
	var err error
	var classDesc = new(TCClassDesc)

	// read JAVA_TC_CLASSDESC flag
	_, _ = stream.ReadN(1)

	// className
	classDesc.ClassName, err = readUTF(stream)
	if err != nil {
		return nil, err
	}

	// serialVersionUID
	classDesc.SerialVersionUID, err = readSerialVersionUID(stream)
	if err != nil {
		return nil, err
	}

	// add handle to reference
	stream.AddReference(classDesc)

	// ------ classDescInfo -------
	// classDescFlags
	bs, err := stream.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("read JAVA_TC_CLASSDESC failed on index %v", stream.CurrentIndex())
	}
	classDesc.ClassDescFlags = bs[0]

	// fields
	classDesc.Fields, err = readTCFields(stream)
	if err != nil {
		return nil, err
	}

	// classAnnotation
	classDesc.ClassAnnotation, err = readTCAnnotation(stream)
	if err != nil {
		return nil, err
	}

	// superClassDesc
	classDesc.SuperClassPointer, err = readTCClassPointer(stream)
	if err != nil {
		return nil, err
	}

	return classDesc, nil
}

func readTCAnnotation(stream *ObjectStream) ([]*TCContent, error) {
	var contents []*TCContent
	for {
		bs, err := stream.PeekN(1)
		if err != nil {
			return nil, fmt.Errorf("read classAnnotation failed on index %v", stream.CurrentIndex())
		}

		if bs[0] == JAVA_TC_ENDBLOCKDATA {
			_, _ = stream.ReadN(1)
			break
		}

		content, err := readTCContent(stream)
		if err != nil {
			return nil, err
		}

		contents = append(contents, content)
	}

	return contents, nil
}

func readTCFields(stream *ObjectStream) ([]*TCFieldDesc, error) {
	var bs []byte
	var err error
	var fields []*TCFieldDesc

	bs, err = stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read JAVA_TC_CLASSDESC failed on index %v", stream.CurrentIndex())
	}
	fieldsLength := binary.BigEndian.Uint16(bs)

	for i := uint16(0); i < fieldsLength; i++ {
		field, err := readTCField(stream)
		if err != nil {
			return nil, err
		}

		fields = append(fields, field)
	}

	return fields, nil
}

func readSerialVersionUID(stream *ObjectStream) (int64, error) {
	bs, err := stream.ReadN(8)
	if err != nil {
		return 0, fmt.Errorf("read SerialVersionUID failed on index %v", stream.CurrentIndex())
	}

	// uint64 to int64 is expected
	return int64(binary.BigEndian.Uint64(bs)), nil
}
