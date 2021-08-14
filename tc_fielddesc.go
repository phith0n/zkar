package javaserialize

import (
	"fmt"
	"github.com/thoas/go-funk"
)

var PrimitiveTypecode = []string{"B", "C", "D", "F", "I", "J", "S", "Z"}
var ObjectTypecode = []string{"[", "L"}
var AllTypecode = append(PrimitiveTypecode, ObjectTypecode...)
var typecodeVerbose = map[string]string {
	"B": "Byte",
	"C": "Char",
	"D": "Double",
	"F": "Float",
	"I": "Integer",
	"J": "Long",
	"S": "Short",
	"Z": "Boolean",
	"[": "Array",
	"L": "Object",
}

type TCFieldDesc struct {
	TypeCode  string
	FieldName *TCUtf
	ClassName *TCStringPointer
}

func (f *TCFieldDesc) ToBytes() []byte {
	bs := []byte(f.TypeCode)
	bs = append(bs, f.FieldName.ToBytes()...)
	if f.TypeCode == "L" || f.TypeCode == "[" {
		bs = append(bs, f.ClassName.ToBytes()...)
	}

	return bs
}

func (f *TCFieldDesc) ToString() string {
	var b = NewPrinter()
	b.Printf("%s - %s - %s\n", typecodeVerbose[f.TypeCode], f.TypeCode, Hexify(f.TypeCode))
	b.Printf("@FieldName \n")
	b.IncreaseIndent()
	b.Printf(f.FieldName.ToString())
	b.DecreaseIndent()
	if f.TypeCode == "L" || f.TypeCode == "[" {
		b.Printf("@ClassName \n")
		b.IncreaseIndent()
		b.Printf(f.ClassName.ToString())
	}

	return b.String()
}

func readTCField(stream *ObjectStream) (*TCFieldDesc, error) {
	var fieldDesc = new(TCFieldDesc)
	typeCode, err := stream.ReadN(1)
	if err != nil {
		sugar.Error(err)
		return nil, fmt.Errorf("read FieldDesc failed on index %v", stream.CurrentIndex())
	}

	fieldDesc.TypeCode = string(typeCode)
	if !funk.ContainsString(AllTypecode, fieldDesc.TypeCode) { // prim typecode
		return nil, fmt.Errorf("read FieldDesc failed on index %v, type code %v is invalid",
			stream.CurrentIndex(),
			fieldDesc.TypeCode,
		)
	}

	if fieldDesc.FieldName, err = readUTF(stream); err != nil {
		return nil, err
	}

	if funk.ContainsString(ObjectTypecode, fieldDesc.TypeCode) {
		fieldDesc.ClassName, err = readTCStringPointer(stream)
		if err != nil {
			return nil, err
		}
	}

	return fieldDesc, nil
}
