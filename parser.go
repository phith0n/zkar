package javaserialize

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"go.uber.org/zap"
)

var logger, _ = zap.NewProduction()
var sugar = logger.Sugar()

type Object interface {
	ToBytes() []byte
}

type ObjectInputStream struct {
	MagicNumber []byte
	StreamVersion []byte
	Objects []Object
	baseHandler int
}

func NewObjectInputStream() *ObjectInputStream {
	return &ObjectInputStream{
		baseHandler: JAVA_BASE_HANDLER,
	}
}

func (ois *ObjectInputStream) ReadObject(data []byte) error {
	var bs []byte
	var err error
	var stream = NewStream(data)

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
		if err = ois.readContentElement(stream); err != nil {
			return err
		}
	}

	return nil
}

func (ois *ObjectInputStream) createHandler() {
	ois.baseHandler += 1
}

func (ois *ObjectInputStream) readContentElement(stream *Stream) error {
	var err error = nil
	switch next, _ := stream.PeekN(1); next[0] {
	case JAVA_TC_STRING:
		err = ois.readNewString(stream)
	case JAVA_TC_LONGSTRING:
		err = ois.readNewLongString(stream)
	}

	return err
}

func (ois *ObjectInputStream) readNewString(stream *Stream) error {
	var bs []byte
	var err error

	// read JAVA_TC_STRING Flag, 0x74
	_, _ = stream.ReadN(1)

	// read JAVA_TC_STRING object length, uint16
	bs, err = stream.ReadN(2)
	if err != nil {
		sugar.Error(err)
		return fmt.Errorf("read JAVA_TC_STRING object failed on index %v", stream.CurrentIndex())
	}

	// read JAVA_TC_STRING object
	length := binary.BigEndian.Uint16(bs)
	data, err := stream.ReadN(int(length))
	if err != nil {
		sugar.Error(err)
		return fmt.Errorf("read JAVA_TC_STRING object failed on index %v", stream.CurrentIndex())
	}

	object := &StringObject{
		data: data,
	}

	ois.Objects = append(ois.Objects, object)
	ois.createHandler()
	return nil
}

func (ois *ObjectInputStream) readNewLongString(stream *Stream) error {
	var bs []byte
	var err error

	// read JAVA_TC_LONGSTRING Flag, 0x74
	_, _ = stream.ReadN(1)

	// read JAVA_TC_LONGSTRING object length, uint16
	bs, err = stream.ReadN(8)
	if err != nil {
		sugar.Error(err)
		return fmt.Errorf("read JAVA_TC_LONGSTRING object failed on index %v", stream.CurrentIndex())
	}

	length := binary.BigEndian.Uint64(bs)
	if length > 0xFFFFFFFF {
		return fmt.Errorf("javaserialize doesn't support JAVA_TC_LONGSTRING longer than 0xFFFFFFFF, but current length is %v", length)
	}

	data, err := stream.ReadN(int(length))
	if err != nil {
		sugar.Error(err)
		return fmt.Errorf("read JAVA_TC_LONGSTRING object failed on index %v", stream.CurrentIndex())
	}

	object := &LongStringObject{
		data: data,
	}

	ois.Objects = append(ois.Objects, object)
	ois.createHandler()
	return nil
}
