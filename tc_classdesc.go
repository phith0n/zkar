package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type TCClassDesc struct {
	Flag byte
	Reference *TCReference
	ClassName *TCString
	SerialVersionUID int64
	ClassDescFlags byte
	Fields []*TCField
	ClassAnnotation []*TCContent
	SuperClassDesc *TCClassDesc
}

func (cdo *TCClassDesc) ToBytes() []byte {
	var result []byte
	switch cdo.Flag {
	case JAVA_TC_NULL:
		result = []byte{JAVA_TC_NULL}
	case JAVA_TC_REFERENCE:
		result = cdo.Reference.ToBytes()
	case JAVA_TC_CLASSDESC:
		result = []byte{JAVA_TC_CLASSDESC}
		result = append(result, cdo.ClassName.ToBytes()...)
		result = append(result, NumberToBytes(cdo.SerialVersionUID)...)
		result = append(result, cdo.ClassDescFlags)
		result = append(result, NumberToBytes(uint16(len(cdo.Fields)))...)
		for _, field := range cdo.Fields {
			result = append(result, field.ToBytes()...)
		}
		for _, content := range cdo.ClassAnnotation {
			result = append(result, content.ToBytes()...)
		}
		result = append(result, JAVA_TC_ENDBLOCKDATA)
		result = append(result, cdo.SuperClassDesc.ToBytes()...)
	}

	return result
}

func readClassDesc(stream *Stream) (*TCClassDesc, error) {
	// read JAVA_TC_CLASSDESC Flag
	flag, _ := stream.PeekN(1)
	if flag[0] == JAVA_TC_NULL {
		_, _ = stream.ReadN(1)
		return &TCClassDesc{Flag: JAVA_TC_NULL}, nil
	} else if flag[0] == JAVA_TC_REFERENCE {
		reference, err := readReference(stream)
		if err != nil {
			return nil, err
		}

		return &TCClassDesc{Flag: JAVA_TC_REFERENCE, Reference: reference}, nil
	} else if flag[0] == JAVA_TC_CLASSDESC {
		return readSimpleClassDesc(stream)
	} else {
		return nil, fmt.Errorf("read ClassDesc failed in index %v", stream.CurrentIndex())
	}
}

func readSimpleClassDesc(stream *Stream) (*TCClassDesc, error) {
	var err error
	var classDesc = new(TCClassDesc)
	classDesc.Flag = JAVA_TC_CLASSDESC

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
	classDesc.ClassAnnotation, err = readClassAnnotation(stream)
	if err != nil {
		return nil, err
	}

	// superClassDesc
	classDesc.SuperClassDesc, err = readClassDesc(stream)
	if err != nil {
		return nil, err
	}

	return classDesc, nil
}

func readClassAnnotation(stream *Stream) ([]*TCContent, error) {
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

func readTCFields(stream *Stream) ([]*TCField, error) {
	var bs []byte
	var err error
	var fields []*TCField

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

func readSerialVersionUID(stream *Stream) (int64, error) {
	bs, err := stream.ReadN(8)
	if err != nil {
		sugar.Error(err)
		return 0, fmt.Errorf("read SerialVersionUID failed on index %v", stream.CurrentIndex())
	}

	// uint64 to int64 is expected
	return int64(binary.BigEndian.Uint64(bs)), nil
}
