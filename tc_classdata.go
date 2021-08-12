package javaserialize

type TCClassData struct {
	FieldDatas []*TCValue
	ObjectAnnotation []*TCContent
}

func (cd *TCClassData) ToBytes() []byte {
	var bs []byte
	for _, value := range cd.FieldDatas {
		bs = append(bs, value.ToBytes()...)
	}

	for _, content := range cd.ObjectAnnotation {
		bs = append(bs, content.ToBytes()...)
	}

	if len(cd.ObjectAnnotation) > 0 {
		bs = append(bs, JAVA_TC_ENDBLOCKDATA)
	}

	return bs
}

func readTCClassData(stream *ObjectStream, desc *TCNormalClassDesc) (*TCClassData, error) {
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

func readTCFieldData(stream *ObjectStream, field *TCFieldDesc) (*TCValue, error) {
	return readTCValue(stream, field.TypeCode)
}
