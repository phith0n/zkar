package javaserialize

type TCClassData struct {
	HasAnnotation bool
	FieldDatas []*TCValue
	ObjectAnnotation []*TCContent
}

func (cd *TCClassData) ToBytes() []byte {
	var bs []byte
	for _, value := range cd.FieldDatas {
		bs = append(bs, value.ToBytes()...)
	}

	if !cd.HasAnnotation {
		return bs
	}

	for _, content := range cd.ObjectAnnotation {
		bs = append(bs, content.ToBytes()...)
	}

	bs = append(bs, JAVA_TC_ENDBLOCKDATA)
	return bs
}

func readTCClassData(stream *ObjectStream, desc *TCClassDesc) (*TCClassData, error) {
	var err error
	var classData = new(TCClassData)
	current := stream.CurrentIndex()
	if desc.HasFlag(JAVA_SC_SERIALIZABLE) {
		for _, field := range desc.Fields {
			fieldData, err := readTCFieldData(stream, field)
			if err == NoFieldError {
				// When java.io.Serializable#defaultWriteObject is not invoke, no built-in field data is written.
				// So we should clear the classData.FieldDatas and reset the position of stream
				// Then everything will be read from objectAnnotation
				// Example: ysoserial C3O0
				stream.Seek(current)
				classData.FieldDatas = []*TCValue{}
				break
			} else if err != nil {
				return nil, err
			}

			classData.FieldDatas = append(classData.FieldDatas, fieldData)
		}
	}

	if (desc.HasFlag(JAVA_SC_SERIALIZABLE) && desc.HasFlag(JAVA_SC_WRITE_METHOD)) ||
		(desc.HasFlag(JAVA_SC_EXTERNALIZABLE) && desc.HasFlag(JAVA_SC_BLOCK_DATA)) {
		classData.HasAnnotation = true
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
