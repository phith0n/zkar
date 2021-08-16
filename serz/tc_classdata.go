package serz

import (
	"io"
)

type ReferenceClassInformation struct {
	ClassName string
	Attributes []string
}

type TCClassData struct {
	HasAnnotation    bool
	ReferenceClass   *ReferenceClassInformation
	FieldDatas       []*TCValue
	ObjectAnnotation []*TCContent
}

func (cd *TCClassData) ToBytes() []byte {
	var bs []byte
	for _, data := range cd.FieldDatas {
		bs = append(bs, data.ToBytes()...)
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
	var b = newPrinter()
	b.printf("@ClassName - %s", cd.ReferenceClass.ClassName)
	b.increaseIndent()
	b.print("{}Attributes")
	b.increaseIndent()
	for i := 0; i < len(cd.FieldDatas); i++ {
		b.printf("%s", cd.ReferenceClass.Attributes[i])
		b.increaseIndent()
		b.print(cd.FieldDatas[i].ToString())
		b.decreaseIndent()
	}
	b.decreaseIndent()

	if !cd.HasAnnotation {
		return b.String()
	}

	b.print("@ObjectAnnotation")
	b.increaseIndent()
	for _, content := range cd.ObjectAnnotation {
		b.print(content.ToString())
	}

	return b.String()
}

func readTCClassData(stream *ObjectStream, desc *TCClassDesc) (*TCClassData, error) {
	var err error
	var classData = &TCClassData{
		ReferenceClass: &ReferenceClassInformation{
			ClassName: desc.ClassName.Data,
		},
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
				stream.Seek(current, io.SeekStart)
				classData.FieldDatas = []*TCValue{}
				break
			} else if err != nil {
				return nil, err
			}

			classData.FieldDatas = append(classData.FieldDatas, fieldData)
			classData.ReferenceClass.Attributes = append(classData.ReferenceClass.Attributes, field.FieldName.Data)
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
