package javaserialize

type TCContent struct {
	String *TCString
	LongString *TCLongString
	BlockData *TCBlockData
}

func (c *TCContent) ToBytes() []byte {
	return nil
}

func readTCContent(stream *Stream) (*TCContent, error) {
	var err error = nil
	var content = new(TCContent)

	switch next, _ := stream.PeekN(1); next[0] {
	case JAVA_TC_STRING:
		content.String, err = readTCString(stream)
	case JAVA_TC_LONGSTRING:
		content.LongString, err = readTCLongString(stream)
	case JAVA_TC_BLOCKDATA:
	case JAVA_TC_BLOCKDATALONG:
		content.BlockData, err = readTCBlockData(stream)
	case JAVA_TC_OBJECT:

	}

	if err != nil {
		return nil, err
	} else {
		return content, nil
	}
}
