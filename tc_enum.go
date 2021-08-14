package javaserialize

type TCEnum struct {
	ClassPointer *TCClassPointer
	ConstantName *TCStringPointer
	Handler uint32
}

func (e *TCEnum) ToBytes() []byte {
	var bs = []byte{JAVA_TC_ENUM}
	bs = append(bs, e.ClassPointer.ToBytes()...)
	bs = append(bs, e.ConstantName.ToBytes()...)
	return bs
}

func (e *TCEnum) ToString() string {
	var b = NewPrinter()
	b.Printf("TC_ENUM - %s", Hexify(JAVA_TC_ENUM))
	b.IncreaseIndent()
	b.Printf(e.ClassPointer.ToString())
	b.Printf("@Handler - %v", e.Handler)
	b.Printf(e.ConstantName.ToString())
	return b.String()
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
