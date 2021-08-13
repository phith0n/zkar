package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type TCClassDesc struct {
	ClassName *TCUtf
	SerialVersionUID int64
	ClassDescFlags byte
	Fields []*TCFieldDesc
	ClassAnnotation []*TCContent
	SuperClassPointer *TCClassPointer
}

func (desc *TCClassDesc) ToBytes() []byte {
	var result = []byte{JAVA_TC_CLASSDESC}
	result = append(result, desc.ClassName.ToBytes()...)
	result = append(result, NumberToBytes(desc.SerialVersionUID)...)
	result = append(result, desc.ClassDescFlags)
	result = append(result, NumberToBytes(uint16(len(desc.Fields)))...)
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

// HasFlag Check if a TCClassDesc object has a flag
func (desc *TCClassDesc) HasFlag(flag byte) bool {
	return (desc.ClassDescFlags & flag) == flag
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
		sugar.Error(err)
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
			sugar.Error(err)
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
		sugar.Error(err)
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
		sugar.Error(err)
		return 0, fmt.Errorf("read SerialVersionUID failed on index %v", stream.CurrentIndex())
	}

	// uint64 to int64 is expected
	return int64(binary.BigEndian.Uint64(bs)), nil
}
