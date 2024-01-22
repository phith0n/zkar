package serz

import "fmt"

type TCContent struct {
	Flag            byte
	Object          *TCObject
	String          *TCString
	Array           *TCArray
	BlockData       *TCBlockData
	Class           *TCClass
	NormalClassDesc *TCClassDesc
	ProxyClassDesc  *TCProxyClassDesc
	Null            *TCNull
	Enum            *TCEnum
	Reference       *TCReference
}

func (c *TCContent) ToBytes() []byte {
	var bs []byte
	switch c.Flag {
	case JAVA_TC_STRING, JAVA_TC_LONGSTRING:
		bs = c.String.ToBytes()
	case JAVA_TC_BLOCKDATA, JAVA_TC_BLOCKDATALONG:
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

func (c *TCContent) ToString() string {
	var bs string
	switch c.Flag {
	case JAVA_TC_STRING, JAVA_TC_LONGSTRING:
		bs = c.String.ToString()
	case JAVA_TC_BLOCKDATA, JAVA_TC_BLOCKDATALONG:
		bs = c.BlockData.ToString()
	case JAVA_TC_CLASS:
		bs = c.Class.ToString()
	case JAVA_TC_OBJECT:
		bs = c.Object.ToString()
	case JAVA_TC_NULL:
		bs = c.Null.ToString()
	case JAVA_TC_REFERENCE:
		bs = c.Reference.ToString()
	case JAVA_TC_ENUM:
		bs = c.Enum.ToString()
	case JAVA_TC_ARRAY:
		bs = c.Array.ToString()
	case JAVA_TC_RESET:
		bs = "TC_RESET"
	}

	return bs
}

func (c *TCContent) Walk(callback WalkCallback) error {
	var obj Object
	switch c.Flag {
	case JAVA_TC_STRING, JAVA_TC_LONGSTRING:
		obj = c.String
	case JAVA_TC_BLOCKDATA, JAVA_TC_BLOCKDATALONG:
		obj = c.BlockData
	case JAVA_TC_CLASS:
		obj = c.Class
	case JAVA_TC_OBJECT:
		obj = c.Object
	case JAVA_TC_NULL:
		obj = c.Null
	case JAVA_TC_REFERENCE:
		obj = c.Reference
	case JAVA_TC_ENUM:
		obj = c.Enum
	case JAVA_TC_ARRAY:
		obj = c.Array
	}

	if err := callback(obj); err != nil {
		return err
	}

	return obj.Walk(callback)
}

func ReadTCContent(stream *ObjectStream) (*TCContent, error) {
	var err error = nil
	var content = new(TCContent)

	next, err := stream.PeekN(1)
	if err != nil {
		return nil, err
	}
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
		content.NormalClassDesc, err = readTCNormalClassDesc(stream)
	case JAVA_TC_PROXYCLASSDESC:
		content.ProxyClassDesc, err = readTCProxyClassDesc(stream)
	case JAVA_TC_NULL:
		content.Null = readTCNull(stream)
	case JAVA_TC_REFERENCE:
		content.Reference, err = readTCReference(stream)
	case JAVA_TC_ARRAY:
		content.Array, err = readTCArray(stream)
	case JAVA_TC_ENUM:
		content.Enum, err = readTCEnum(stream)
	default:
		err = fmt.Errorf("illegal character %v found on index %v", next, stream.CurrentIndex())
	}

	if err != nil {
		return nil, err
	} else {
		return content, nil
	}
}
