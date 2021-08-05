package javaserialize

type TCField struct {
	TypeCode string
	FieldName *TCString
	ClassName *TCString
}

func (f *TCField) ToBytes() []byte {
	bs := []byte(f.TypeCode)
	bs = append(bs, f.FieldName.ToBytes()...)
	if f.TypeCode == "L" || f.TypeCode == "[" {
		bs = append(bs, JAVA_TC_STRING)
		bs = append(bs, f.ClassName.ToBytes()...)
	}

	return bs
}

func readTCField(stream *Stream) (*TCField, error) {
	return nil, nil
}
