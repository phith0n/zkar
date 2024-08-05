package serz

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/phith0n/zkar/commons"
)

type Object interface {
	ToBytes() []byte
	ToString() string
	AllowWalked
}

type Serialization struct {
	MagicNumber   []byte
	StreamVersion []byte
	Contents      []*TCContent
}

func FromReader(r io.Reader) (*Serialization, error) {
	var stream = NewObjectStreamFromReader(r)
	var ser = new(Serialization)

	// read magic number 0xACED
	bs, err := stream.ReadN(2)
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

	for {
		var content *TCContent
		content, err = ReadTCContent(stream)
		if err != nil {
			if err == io.EOF {
				return ser, nil
			}
			return nil, err
		}

		ser.Contents = append(ser.Contents, content)
	}
}

func FromReadSeeker(r io.ReadSeeker) (*Serialization, error) {
	return FromReader(r)
}

func FromBytes(data []byte) (*Serialization, error) {
	return FromReader(bytes.NewReader(data))
}

func FromJDK8u20Bytes(data []byte) (*Serialization, error) {
	data = bytes.Replace(
		data,
		[]byte{0x00, 0x7e, 0x00, 0x09},
		[]byte{0x00, 0x7e, 0x00, 0x09, JAVA_TC_ENDBLOCKDATA},
		1,
	)
	return FromBytes(data)
}

func (ois *Serialization) ToString() string {
	var b = commons.NewPrinter()
	b.Printf("@Magic - %s", commons.Hexify(ois.MagicNumber))
	b.Printf("@Version - %s", commons.Hexify(ois.StreamVersion))
	b.Printf("@Contents")
	b.IncreaseIndent()
	for _, content := range ois.Contents {
		b.Print(content.ToString())
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

func (ois *Serialization) ToJDK8u20Bytes() []byte {
	var data = ois.ToBytes()
	return bytes.Replace(
		data,
		[]byte{0x00, 0x7e, 0x00, 0x09, JAVA_TC_ENDBLOCKDATA},
		[]byte{0x00, 0x7e, 0x00, 0x09},
		1,
	)
}

func (ois *Serialization) Walk(callback WalkCallback) error {
	for _, content := range ois.Contents {
		if err := callback(content); err != nil {
			return err
		}

		if err := content.Walk(callback); err != nil {
			return err
		}
	}

	return nil
}
