package javaserialize

type TCClass struct {
	ClassPointer *TCClassPointer
	Handler uint32
}

func (c *TCClass) ToBytes() []byte {
	var bs = []byte{JAVA_TC_CLASS}
	bs = append(bs, c.ClassPointer.ToBytes()...)
	return bs
}

func (c *TCClass) ToString() string {
	var b = NewPrinter()
	b.Printf("TC_CLASS - %s\n", Hexify(JAVA_TC_CLASS))
	b.IncreaseIndent()
	b.Printf(c.ClassPointer.ToString())
	b.Printf("@Handler - %v", c.Handler)
	return b.String()
}

func readTCClass(stream *ObjectStream) (*TCClass, error) {
	var class = new(TCClass)
	var err error

	_, _ = stream.ReadN(1)
	class.ClassPointer, err = readTCClassPointer(stream)
	if err != nil {
		return nil, err
	}

	stream.AddReference(class)
	return class, nil
}
