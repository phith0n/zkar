package serz

import "github.com/phith0n/zkar/commons"

type TCNull struct {
	// nothing
}

func (n *TCNull) ToBytes() []byte {
	return []byte{JAVA_TC_NULL}
}

func (n *TCNull) ToString() string {
	var b = commons.NewPrinter()
	b.Printf("TC_NULL - %s", commons.Hexify(JAVA_TC_NULL))
	return b.String()
}

func (n *TCNull) Walk(callback WalkCallback) error {
	return nil
}

func readTCNull(stream *ObjectStream) *TCNull {
	_, _ = stream.ReadN(1)
	return new(TCNull)
}
