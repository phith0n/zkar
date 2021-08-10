package javaserialize

type TCContent struct {
	Object *TCObject
	String *TCString
	BlockData *TCBlockData
	Class *TCClass
	Null *TCNull
	Reference *TCReference
}

func (c *TCContent) ToBytes() []byte {
	return nil
}

func readTCContent(stream *ObjectStream) (*TCContent, error) {
	var err error = nil
	var content = new(TCContent)

	switch next, _ := stream.PeekN(1); next[0] {
	case JAVA_TC_STRING, JAVA_TC_LONGSTRING:
		content.String, err = readTCString(stream)
	case JAVA_TC_BLOCKDATA:
	case JAVA_TC_BLOCKDATALONG:
		content.BlockData, err = readTCBlockData(stream)
	case JAVA_TC_OBJECT:
		content.Object, err = readTCObject(stream)
	case JAVA_TC_CLASS:
		content.Class, err = readTCClass(stream)
	case JAVA_TC_NULL:
		content.Null = readTCNull(stream)
	case JAVA_TC_REFERENCE:
		content.Reference, err = readTCReference(stream)
	}

	if err != nil {
		return nil, err
	} else {
		return content, nil
	}
}
