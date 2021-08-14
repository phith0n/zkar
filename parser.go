package javaserialize

import (
	"bytes"
	"fmt"
	"go.uber.org/zap"
)

var logger, _ = zap.NewProduction()
var sugar = logger.Sugar()

type Object interface {
	ToBytes() []byte
	ToString() string
}

type ObjectInputStream struct {
	MagicNumber   []byte
	StreamVersion []byte
	Contents      []*TCContent
}

func NewObjectInputStream() *ObjectInputStream {
	return &ObjectInputStream{}
}

func (ois *ObjectInputStream) ToString() string {
	var b = NewPrinter()
	b.Printf("@magic - %s\n", Hexify(ois.MagicNumber))
	b.Printf("@version - %s\n", Hexify(ois.StreamVersion))
	b.Printf("@contents \n")
	b.IncreaseIndent()
	for _, content := range ois.Contents {
		b.Printf(content.ToString())
		b.Printf("\n")
	}
	return b.String()
}

func (ois *ObjectInputStream) ToBytes() []byte {
	var bs = append(ois.MagicNumber, ois.StreamVersion...)
	for _, content := range ois.Contents {
		bs = append(bs, content.ToBytes()...)
	}

	return bs
}

func (ois *ObjectInputStream) Read(data []byte) error {
	var bs []byte
	var err error
	var stream = NewObjectStream(data)

	// read magic number 0xACED
	bs, err = stream.ReadN(2)
	if err != nil || !bytes.Equal(bs, JAVA_STREAM_MAGIC) {
		return fmt.Errorf("invalid magic number")
	}
	ois.MagicNumber = JAVA_STREAM_MAGIC

	// read stream version
	bs, err = stream.ReadN(2)
	if err != nil || !bytes.Equal(bs, JAVA_STREAM_VERSION) {
		sugar.Warnf("invalid stream version %v", bs)
	}
	ois.StreamVersion = bs

	for !stream.EOF() {
		var content *TCContent
		content, err = readTCContent(stream)
		if err != nil {
			return err
		}

		ois.Contents = append(ois.Contents, content)
	}

	return nil
}
