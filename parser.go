package javaserialize

import (
	"bytes"
	"fmt"
)

type ObjectStream struct {
	MagicNumber []byte
	StreamVersion []byte
}

func (os *ObjectStream) ReadObject(data []byte) error {
	var bs []byte
	var err error
	var stream = NewStream(data)
	bs, err = stream.ReadN(2)
	if err != nil || !bytes.Equal(bs, JAVA_STREAM_MAGIC) {
		return fmt.Errorf("invalid magic number")
	}

	os.MagicNumber = JAVA_STREAM_MAGIC
	bs, err = stream.ReadN(2)
	if err != nil || !bytes.Equal(bs, JAVA_STREAM_VERSION) {
		return fmt.Errorf("invalid stream version")
	}

	return nil
}
