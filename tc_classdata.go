package javaserialize

type TCClassData struct {
	FieldDatas []*TCFieldData
	ObjectAnnotation []*TCContent
}

func (cd *TCClassData) ToBytes() []byte {
	return nil
}

func readTCClassData(stream *Stream, desc *TCClassDesc) (*TCClassData, error) {
	var err error
	var classData = new(TCClassData)
	if desc.HasFlag(JAVA_SC_SERIALIZABLE) {
		for _, field := range desc.Fields {
			fieldData, err := readTCFieldData(stream, field)
			if err != nil {
				return nil, err
			}

			classData.FieldDatas = append(classData.FieldDatas, fieldData)
		}
	}

	if (desc.HasFlag(JAVA_SC_SERIALIZABLE) && desc.HasFlag(JAVA_SC_WRITE_METHOD)) ||
		(desc.HasFlag(JAVA_SC_EXTERNALIZABLE) && desc.HasFlag(JAVA_SC_BLOCK_DATA)) {
		classData.ObjectAnnotation, err = readTCAnnotation(stream)
		if err != nil {
			return nil, err
		}
	}

	return classData, nil
}

func readTCFieldData(stream *Stream, field *TCFieldDesc) (*TCFieldData, error) {
	return field.read(stream)
}
