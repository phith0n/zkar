package serz

import "github.com/phith0n/zkar/commons"

type TCEnum struct {
	ClassPointer *TCClassPointer
	ConstantName *TCStringPointer
	Handler      uint32
}

func (e *TCEnum) ToBytes() []byte {
	var bs = []byte{JAVA_TC_ENUM}
	bs = append(bs, e.ClassPointer.ToBytes()...)
	bs = append(bs, e.ConstantName.ToBytes()...)
	return bs
}

func (e *TCEnum) ToString() string {
	var b = commons.NewPrinter()
	b.Printf("TC_ENUM - %s", commons.Hexify(JAVA_TC_ENUM))
	b.IncreaseIndent()
	b.Print(e.ClassPointer.ToString())
	b.Printf("@Handler - %v", e.Handler)
	b.Print(e.ConstantName.ToString())
	return b.String()
}

func (e *TCEnum) Walk(callback WalkCallback) error {
	if err := callback(e.ClassPointer); err != nil {
		return err
	}

	if err := e.ClassPointer.Walk(callback); err != nil {
		return err
	}

	if err := callback(e.ConstantName); err != nil {
		return err
	}

	return e.ConstantName.Walk(callback)
}

func readTCEnum(stream *ObjectStream) (*TCEnum, error) {
	var enum = new(TCEnum)
	var err error

	_, _ = stream.ReadN(1)
	enum.ClassPointer, err = readTCClassPointer(stream)
	if err != nil {
		return nil, err
	}

	stream.AddReference(enum)
	enum.ConstantName, err = readTCStringPointer(stream)
	if err != nil {
		return nil, err
	}

	return enum, nil
}
