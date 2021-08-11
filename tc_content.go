package javaserialize

type TCContent struct {
	Flag byte
	Object *TCObject
	String *TCString
	Array *TCArray
	BlockData *TCBlockData
	Class *TCClass
	ClassDesc *TCClassDesc
	Null *TCNull
	Enum *TCEnum
	Reference *TCReference
}

func (c *TCContent) ToBytes() []byte {
	var bs []byte
	switch c.Flag {
	case JAVA_TC_STRING, JAVA_TC_LONGSTRING:
		bs = c.String.ToBytes()
	case JAVA_TC_BLOCKDATA, JAVA_TC_LONGSTRING:
		bs = c.BlockData.ToBytes()
	case JAVA_TC_CLASS:
		bs = c.Class.ToBytes()
	case JAVA_TC_OBJECT:
		bs = c.Object.ToBytes()
	case JAVA_TC_NULL:
		bs = c.Null.ToBytes()
	case JAVA_TC_REFERENCE:
		bs = c.Reference.ToBytes()
	case JAVA_TC_ENUM:
		bs = c.Enum.ToBytes()
	case JAVA_TC_ARRAY:
		bs = c.Array.ToBytes()
	case JAVA_TC_RESET:
		bs = []byte{JAVA_TC_RESET}
	}

	return bs
}

func readTCContent(stream *ObjectStream) (*TCContent, error) {
	var err error = nil
	var content = new(TCContent)

	next, _ := stream.PeekN(1)
	content.Flag = next[0]
	switch next[0] {
	case JAVA_TC_STRING, JAVA_TC_LONGSTRING:
		content.String, err = readTCString(stream)
	case JAVA_TC_BLOCKDATA, JAVA_TC_BLOCKDATALONG:
		content.BlockData, err = readTCBlockData(stream)
	case JAVA_TC_OBJECT:
		content.Object, err = readTCObject(stream)
	case JAVA_TC_CLASS:
		content.Class, err = readTCClass(stream)
	case JAVA_TC_CLASSDESC:
		content.ClassDesc, err = readTCClassDesc(stream, nil)
	case JAVA_TC_NULL:
		content.Null = readTCNull(stream)
	case JAVA_TC_REFERENCE:
		content.Reference, err = readTCReference(stream)
	case JAVA_TC_ARRAY:
		content.Array, err = readTCArray(stream)
	case JAVA_TC_ENUM:
		content.Enum, err = readTCEnum(stream)
	}

	if err != nil {
		return nil, err
	} else {
		return content, nil
	}
}
