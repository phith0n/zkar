package javaserialize

type TCNull struct {
	// nothing
}

func (n *TCNull) ToBytes() []byte {
	return []byte{JAVA_TC_NULL}
}

func readTCNull(stream *Stream) *TCNull {
	_, _ = stream.ReadN(1)
	return new(TCNull)
}
