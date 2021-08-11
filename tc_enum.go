package javaserialize

type TCEnum struct {
	ClassPointer *TCClassPointer
	ConstantName *TCString
}

func (e *TCEnum) ToBytes() []byte {
	var bs = []byte{JAVA_TC_ENUM}
	bs = append(bs, e.ClassPointer.ToBytes()...)
	bs = append(bs, e.ConstantName.ToBytes()...)
	return bs
}

func readTCEnum(stream *ObjectStream) (*TCEnum, error) {
	var enum = new(TCEnum)
	var err error

	_, _ = stream.ReadN(1)
	enum.ClassPointer, err = readTCClassPointer(stream, nil)
	if err != nil {
		return nil, err
	}

	stream.AddReference(enum)
	enum.ConstantName, err = readTCString(stream)
	if err != nil {
		return nil, err
	}

	return enum, nil
}
