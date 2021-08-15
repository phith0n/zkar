package zkar

import (
	"bytes"
	"fmt"
	"os"
)

type Object interface {
	ToBytes() []byte
	ToString() string
}

type Serialization struct {
	MagicNumber   []byte
	StreamVersion []byte
	Contents      []*TCContent
}

func FromBytes(data []byte) (*Serialization, error) {
	var bs []byte
	var err error
	var stream = NewObjectStream(data)
	var ser = new(Serialization)

	// read magic number 0xACED
	bs, err = stream.ReadN(2)
	if err != nil || !bytes.Equal(bs, JAVA_STREAM_MAGIC) {
		return nil, fmt.Errorf("invalid magic number")
	}
	ser.MagicNumber = JAVA_STREAM_MAGIC

	// read stream version
	bs, err = stream.ReadN(2)
	if err != nil || !bytes.Equal(bs, JAVA_STREAM_VERSION) {
		fmt.Fprintf(os.Stderr, "[warn] invalid stream version %v", bs)
	}
	ser.StreamVersion = bs

	for !stream.EOF() {
		var content *TCContent
		content, err = readTCContent(stream)
		if err != nil {
			return nil, err
		}

		ser.Contents = append(ser.Contents, content)
	}

	return ser, nil
}

func (ois *Serialization) ToString() string {
	var b = NewPrinter()
	b.Printf("@Magic - %s", Hexify(ois.MagicNumber))
	b.Printf("@Version - %s", Hexify(ois.StreamVersion))
	b.Printf("@Contents")
	b.IncreaseIndent()
	for _, content := range ois.Contents {
		b.Printf(content.ToString())
	}
	return b.String()
}

func (ois *Serialization) ToBytes() []byte {
	var bs = append(ois.MagicNumber, ois.StreamVersion...)
	for _, content := range ois.Contents {
		bs = append(bs, content.ToBytes()...)
	}

	return bs
}
