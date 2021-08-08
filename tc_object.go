package javaserialize

type TCObject struct {
	ClassPointer *TCClassPointer
	ClassDatas []*TCClassData
}

func (oo *TCObject) ToBytes() []byte {
	return nil
}

func readTCObject(stream *Stream) (*TCObject, error) {
	var obj = new(TCObject)
	var err error

	_, _ = stream.ReadN(1)
	obj.ClassPointer, err = readTCClassPointer(stream)
	if err != nil {
		return nil, err
	}

	if obj.ClassPointer.Flag == JAVA_TC_NULL {
		return obj, nil
	} else if obj.ClassPointer.Flag == JAVA_TC_REFERENCE {
		// TODO: deal with reference
		return obj, nil
	}

	classData, err := readTCClassData(stream, obj.ClassPointer.ClassDesc)
	if err != nil {
		return nil, err
	}

	obj.ClassDatas = append(obj.ClassDatas, classData)
	for obj.ClassPointer.ClassDesc.SuperClassPointer.Flag != JAVA_TC_NULL {
		// TODO: reference
		superClassDesc := obj.ClassPointer.ClassDesc.SuperClassPointer.ClassDesc
		classData, err = readTCClassData(stream, superClassDesc)
		if err != nil {
			return nil, err
		}

		obj.ClassDatas = append(obj.ClassDatas, classData)
	}

	return obj, nil
}
