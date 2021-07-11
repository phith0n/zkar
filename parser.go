package javaserialize

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
)

type ObjectStream struct {
	MagicNumber []byte
	StreamVersion int
}

func (os *ObjectStream) ReadObject(data []byte) error {
	var bs []byte
	var err error
	var reader = bufio.NewReader(bytes.NewReader(data))
	bs, err = os.ReadN(reader, 2)
	if err != nil || !bytes.Equal(bs, JAVA_STREAM_MAGIC) {
		return fmt.Errorf("invalid magic number")
	}

	os.MagicNumber = JAVA_STREAM_MAGIC
	bs, err = os.ReadN(reader, 4)
	if err != nil {
		return fmt.Errorf("invalid stream version")
	}

	return nil
}

func (os *ObjectStream) ReadN(reader *bufio.Reader, n int) ([]byte, error) {
	var res = make([]byte, n)
	_, err := io.ReadFull(reader, res)
	if err != nil {
		return nil, err
	} else {
		return res, nil
	}
}

func (os *ObjectStream) PeekN(reader *bufio.Reader, n int) ([]byte, error) {
	return reader.Peek(n)
}
