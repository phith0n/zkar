package javaserialize

type TCObject struct {
	ClassPointer *TCClassPointer
	ClassDatas []*TCClassData
}

func (oo *TCObject) ToBytes() []byte {
	var bs = []byte{JAVA_TC_OBJECT}
	bs = append(bs, oo.ClassPointer.ToBytes()...)
	for _, data := range oo.ClassDatas {
		bs = append(bs, data.ToBytes()...)
	}

	return bs
}

func readTCObject(stream *ObjectStream) (*TCObject, error) {
	var obj = new(TCObject)
	var err error
	var classes []*TCClassDesc // save current TCClassDesc

	_, _ = stream.ReadN(1)
	obj.ClassPointer, err = readTCClassPointer(stream, classes)
	if err != nil {
		return nil, err
	}

	stream.AddReference(obj)
	if obj.ClassPointer.Flag == JAVA_TC_NULL {
		return obj, nil
	} else if obj.ClassPointer.Flag == JAVA_TC_REFERENCE {
		classData, err := readTCClassData(stream, obj.ClassPointer.Reference.ClassDesc)
		if err != nil {
			return nil, err
		}

		obj.ClassDatas = append(obj.ClassDatas, classData)
		return obj, nil
	}

	for _, classDesc := range classes {
		classData, err := readTCClassData(stream, classDesc)
		if err != nil {
			return nil, err
		}

		obj.ClassDatas = append(obj.ClassDatas, classData)
	}

	return obj, nil
}
