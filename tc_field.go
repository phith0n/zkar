package javaserialize

import (
	"encoding/binary"
	"fmt"
	"github.com/thoas/go-funk"
	"math"
)

var PRIMITIVE_TYPECODE = []string{"B", "C", "D", "F", "I", "J", "S", "Z"}
var OBJECT_TYPECODE = []string{"[", "L"}
var ALL_TYPECODE = append(PRIMITIVE_TYPECODE, OBJECT_TYPECODE...)
var SIZE_TABLE = map[string]int {
	"B": 1,
	"C": 2,
	"D": 8,
	"F": 4,
	"I": 4,
	"J": 8,
	"S": 2,
	"Z": 1,
}

type TCFieldDesc struct {
	TypeCode string
	FieldName *TCString
	ClassName *TCString
}

type TCFieldData struct {
	TypeCode string
	BData byte // byte in Java
	CData uint32 // char in Java
	DData float64 // double in Java
	FData float32 // float in Java
	IData int32 // int in Java
	JData int64 // long in Java
	SData int16 // short in Java
	ZData bool // bool in Java
	LData Object // object in Java
	// TODO: array data
}

func (f *TCFieldDesc) ToBytes() []byte {
	bs := []byte(f.TypeCode)
	bs = append(bs, f.FieldName.ToBytes()...)
	if f.TypeCode == "L" || f.TypeCode == "[" {
		bs = append(bs, JAVA_TC_STRING)
		bs = append(bs, f.ClassName.ToBytes()...)
	}

	return bs
}

func (f *TCFieldDesc) read(stream *Stream) (*TCFieldData, error) {
	if funk.ContainsString(PRIMITIVE_TYPECODE, f.TypeCode) {
		return f.readPrimitive(stream)
	} else if f.TypeCode == "L" {
		return f.readObject(stream)
	} else {
		return f.readArray(stream)
	}
}

func (f *TCFieldDesc) readPrimitive(stream *Stream) (*TCFieldData, error) {
	var bs []byte
	var err error

	var size = SIZE_TABLE[f.TypeCode]
	bs, err = stream.ReadN(size)
	if err != nil {
		return nil, fmt.Errorf("read primitive field value failed on index %v", stream.CurrentIndex())
	}

	var fieldData = &TCFieldData{TypeCode: f.TypeCode}
	switch f.TypeCode {
	case "B": // byte
		fieldData.BData = bs[0]
	case "C": // char
		fieldData.CData = binary.BigEndian.Uint32(bs)
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

func (f *TCFieldDesc) readObject(stream *Stream) (*TCFieldData, error) {
	flag, err := stream.PeekN(1)
	if err != nil {
		return nil, fmt.Errorf("read object field value failed on index %v", stream.CurrentIndex())
	}

	var fieldData = &TCFieldData{TypeCode: f.TypeCode}
	switch flag[0] {
	case JAVA_TC_OBJECT:
		fieldData.LData, err = readTCObject(stream)
	case JAVA_TC_NULL:
		fieldData.LData = readTCNull(stream)
		// TODO
	}

	if err != nil {
		return nil, err
	}

	return fieldData, nil
}

func (f *TCFieldDesc) readArray(stream *Stream) (*TCFieldData, error) {
	// TODO
	return nil, nil
}

func readTCField(stream *Stream) (*TCFieldDesc, error) {
	var fieldDesc = new(TCFieldDesc)
	typeCode, err := stream.ReadN(1)
	if err != nil {
		sugar.Error(err)
		return nil, fmt.Errorf("read FieldDesc failed on index %v", stream.CurrentIndex())
	}

	fieldDesc.TypeCode = string(typeCode)
	if !funk.ContainsString(ALL_TYPECODE, fieldDesc.TypeCode) { // prim typecode
		return nil, fmt.Errorf("read FieldDesc failed on index %v, type code %v is invalid",
			stream.CurrentIndex(),
			fieldDesc.TypeCode,
		)
	}

	if fieldDesc.FieldName, err = readUTF(stream); err != nil {
		return nil, err
	}

	if funk.ContainsString(OBJECT_TYPECODE, fieldDesc.TypeCode) {
		fieldDesc.ClassName, err = readTCString(stream)
		if err != nil {
			return nil, err
		}
	}

	return fieldDesc, nil
}
