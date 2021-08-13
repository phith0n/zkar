package javaserialize

import (
	"encoding/binary"
	"fmt"
	"github.com/thoas/go-funk"
	"math"
)

var NoFieldError = fmt.Errorf("Oops!")
var SizeTable = map[string]int{
	"B": 1,
	"C": 2,
	"D": 8,
	"F": 4,
	"I": 4,
	"J": 8,
	"S": 2,
	"Z": 1,
}

type TCValue struct {
	TypeCode string
	BData    byte    // byte in Java
	CData    uint16  // char in Java
	DData    float64 // double in Java
	FData    float32 // float in Java
	IData    int32   // int in Java
	JData    int64   // long in Java
	SData    int16   // short in Java
	ZData    bool    // bool in Java
	LData    Object  // object in Java
}

func (t *TCValue) ToBytes() []byte {
	if t.TypeCode == "L" || t.TypeCode == "[" {
		return t.LData.ToBytes()
	}

	switch t.TypeCode {
	case "B":
		return []byte{t.BData}
	case "C":
		return NumberToBytes(t.CData)
	case "D":
		return NumberToBytes(math.Float64bits(t.DData))
	case "F":
		return NumberToBytes(math.Float32bits(t.FData))
	case "I":
		return NumberToBytes(t.IData)
	case "J":
		return NumberToBytes(t.JData)
	case "S":
		return NumberToBytes(t.SData)
	case "Z":
		if t.ZData {
			return []byte{0x01}
		} else {
			return []byte{0x00}
		}
	}

	return nil
}

func readTCValue(stream *ObjectStream, typeCode string) (*TCValue, error) {
	if funk.ContainsString(PrimitiveTypecode, typeCode) {
		return readTCValueFromPrimitive(stream, typeCode)
	} else {
		return readTCValueFromObject(stream, typeCode)
	}
}

func readTCValueFromPrimitive(stream *ObjectStream, typeCode string) (*TCValue, error) {
	var bs []byte
	var err error

	var size = SizeTable[typeCode]
	bs, err = stream.ReadN(size)
	if err != nil {
		return nil, fmt.Errorf("read primitive field value failed on index %v", stream.CurrentIndex())
	}

	var fieldData = &TCValue{TypeCode: typeCode}
	switch typeCode {
	case "B": // byte
		fieldData.BData = bs[0]
	case "C": // char
		fieldData.CData = binary.BigEndian.Uint16(bs)
	case "D": // double
		bits := binary.BigEndian.Uint64(bs)
		fieldData.DData = math.Float64frombits(bits)
	case "F": // float
		bits := binary.BigEndian.Uint32(bs)
		fieldData.FData = math.Float32frombits(bits)
	case "I": // int
		fieldData.IData = int32(binary.BigEndian.Uint32(bs))
	case "J": // long
		fieldData.JData = int64(binary.BigEndian.Uint64(bs))
	case "S": // short
		fieldData.SData = int16(binary.BigEndian.Uint16(bs))
	case "Z": // boolean
		fieldData.ZData = bs[0] != 0x00
	}

	return fieldData, nil
}

func readTCValueFromObject(stream *ObjectStream, typeCode string) (*TCValue, error) {
	flag, err := stream.PeekN(1)
	if err != nil {
		return nil, fmt.Errorf("read object field value failed on index %v", stream.CurrentIndex())
	}

	var fieldData = &TCValue{TypeCode: typeCode}
	switch flag[0] {
	case JAVA_TC_OBJECT:
		fieldData.LData, err = readTCObject(stream)
	case JAVA_TC_NULL:
		fieldData.LData = readTCNull(stream)
	case JAVA_TC_STRING:
		fieldData.LData, err = readTCString(stream)
	case JAVA_TC_REFERENCE:
		fieldData.LData, err = readTCReference(stream)
	case JAVA_TC_CLASS:
		fieldData.LData, err = readTCClass(stream)
	case JAVA_TC_ARRAY:
		fieldData.LData, err = readTCArray(stream)
	case JAVA_TC_ENUM:
		fieldData.LData, err = readTCEnum(stream)
	default:
		err = NoFieldError
	}

	if err != nil {
		return nil, err
	}

	return fieldData, nil
}

//func readTCValueFromArray(stream *ObjectStream, typeCode string) (*TCValue, error) {
//	flag, err := stream.PeekN(1)
//	if err != nil {
//		sugar.Error(err)
//		return nil, fmt.Errorf("read array field value failed on index %v", stream.CurrentIndex())
//	}
//
//	switch flag[0] {
//	case JAVA_TC_STRING:
//
//	}
//
//	return nil, nil
//}
