package javaserialize

import orderedmap "github.com/wk8/go-ordered-map"

type TCClassData struct {
	HasAnnotation    bool
	ReferenceClassName string
	FieldDatas       *orderedmap.OrderedMap
	ObjectAnnotation []*TCContent
}

func (cd *TCClassData) ToBytes() []byte {
	var bs []byte
	for pair := cd.FieldDatas.Oldest(); pair != nil; pair = pair.Next() {
		bs = append(bs, pair.Value.(Object).ToBytes()...)
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

func (cd *TCClassData) ToString() string {
	var b = NewPrinter()
	b.Printf("@ClassName - %s\n", cd.ReferenceClassName)
	b.IncreaseIndent()
	b.Printf("{}Attributes \n")
	b.IncreaseIndent()
	for pair := cd.FieldDatas.Oldest(); pair != nil; pair = pair.Next() {
		b.Printf("%s\n", pair.Key.(string))
		b.IncreaseIndent()
		b.Printf(pair.Value.(Object).ToString())
		b.DecreaseIndent()
		b.Printf("\n")
	}
	b.DecreaseIndent()

	if !cd.HasAnnotation {
		return b.String()
	}

	b.Printf("@ObjectAnnotation \n")
	b.IncreaseIndent()
	for _, content := range cd.ObjectAnnotation {
		b.Printf(content.ToString())
	}

	return b.String()
}

func readTCClassData(stream *ObjectStream, desc *TCClassDesc) (*TCClassData, error) {
	var err error
	var classData = &TCClassData{
		ReferenceClassName: desc.ClassName.Data,
		FieldDatas: orderedmap.New(),
	}

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
				classData.FieldDatas = orderedmap.New()
				break
			} else if err != nil {
				return nil, err
			}

			classData.FieldDatas.Set(field.FieldName.Data, fieldData)
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
