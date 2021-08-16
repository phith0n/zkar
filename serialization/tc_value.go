package serialization

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
	Byte     byte    // byte in Java
	Char     uint16  // char in Java
	Double   float64 // double in Java
	Float    float32 // float in Java
	Integer  int32   // int in Java
	Long     int64   // long in Java
	Short    int16   // short in Java
	Boolean  bool    // bool in Java
	Object   Object  // object in Java
}

func (t *TCValue) ToBytes() []byte {
	if t.TypeCode == "L" || t.TypeCode == "[" {
		return t.Object.ToBytes()
	}

	switch t.TypeCode {
	case "B":
		return []byte{t.Byte}
	case "C":
		return NumberToBytes(t.Char)
	case "D":
		return NumberToBytes(math.Float64bits(t.Double))
	case "F":
		return NumberToBytes(math.Float32bits(t.Float))
	case "I":
		return NumberToBytes(t.Integer)
	case "J":
		return NumberToBytes(t.Long)
	case "S":
		return NumberToBytes(t.Short)
	case "Z":
		if t.Boolean {
			return []byte{0x01}
		} else {
			return []byte{0x00}
		}
	}

	return nil
}

func (t *TCValue) ToString() string {
	var b = newPrinter()
	switch t.TypeCode {
	case "B":
		b.printf("(byte)%v - %s", t.Byte, Hexify(t.Byte))
	case "C":
		b.printf("(char)%v - %s", t.Char, Hexify(t.Char))
	case "D":
		b.printf("(double)%v - %s", t.Double, Hexify(t.Double))
	case "F":
		b.printf("(float)%v - %s", t.Float, Hexify(t.Float))
	case "I":
		b.printf("(integer)%v - %s", t.Integer, Hexify(t.Integer))
	case "J":
		b.printf("(long)%v - %s", t.Long, Hexify(t.Long))
	case "S":
		b.printf("(short)%v - %s", t.Short, Hexify(t.Short))
	case "Z":
		b.printf("(boolean)%v - %s", t.Boolean, Hexify(t.Boolean))
	case "L", "[":
		b.print(t.Object.ToString())
	}

	return b.String()
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
		fieldData.Byte = bs[0]
	case "C": // char
		fieldData.Char = binary.BigEndian.Uint16(bs)
	case "D": // double
		bits := binary.BigEndian.Uint64(bs)
		fieldData.Double = math.Float64frombits(bits)
	case "F": // float
		bits := binary.BigEndian.Uint32(bs)
		fieldData.Float = math.Float32frombits(bits)
	case "I": // int
		fieldData.Integer = int32(binary.BigEndian.Uint32(bs))
	case "J": // long
		fieldData.Long = int64(binary.BigEndian.Uint64(bs))
	case "S": // short
		fieldData.Short = int16(binary.BigEndian.Uint16(bs))
	case "Z": // boolean
		fieldData.Boolean = bs[0] != 0x00
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
		fieldData.Object, err = readTCObject(stream)
	case JAVA_TC_NULL:
		fieldData.Object = readTCNull(stream)
	case JAVA_TC_STRING:
		fieldData.Object, err = readTCString(stream)
	case JAVA_TC_REFERENCE:
		fieldData.Object, err = readTCReference(stream)
	case JAVA_TC_CLASS:
		fieldData.Object, err = readTCClass(stream)
	case JAVA_TC_ARRAY:
		fieldData.Object, err = readTCArray(stream)
	case JAVA_TC_ENUM:
		fieldData.Object, err = readTCEnum(stream)
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
