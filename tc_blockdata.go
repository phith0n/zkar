package zkar

import (
	"encoding/binary"
	"fmt"
)

type TCBlockData struct {
	Data []byte
}

func (bd *TCBlockData) ToBytes() []byte {
	var bs []byte
	if len(bd.Data) > 0xFF {
		bs = append(bs, JAVA_TC_BLOCKDATALONG)
		bs = append(bs, NumberToBytes(uint32(len(bd.Data)))...)
	} else {
		bs = append(bs, JAVA_TC_BLOCKDATA)
		bs = append(bs, NumberToBytes(uint8(len(bd.Data)))...)
	}

	return append(bs, bd.Data...)
}

func (bd *TCBlockData) ToString() string {
	var b = NewPrinter()
	if len(bd.Data) > 0xFF {
		b.Printf("TC_BLOCKDATALONG - %s", Hexify(JAVA_TC_BLOCKDATALONG))
	} else {
		b.Printf("TC_BLOCKDATA - %s", Hexify(JAVA_TC_BLOCKDATA))
	}
	b.IncreaseIndent()
	b.Printf("@Blockdata - %s", Hexify(bd.Data))
	return b.String()
}

func readTCBlockData(stream *ObjectStream) (*TCBlockData, error) {
	// read JAVA_TC_BLOCKDATA or JAVA_TC_BLOCKDATALONG Flag
	flag, _ := stream.ReadN(1)
	var length int
	if flag[0] == JAVA_TC_BLOCKDATA {
		lengthBs, err := stream.ReadN(1)
		if err != nil {
			return nil, fmt.Errorf("read JAVA_TC_BLOCKDATA object failed on index %v", stream.CurrentIndex())
		}

		length = int(lengthBs[0])
	} else {
		lengthBs, err := stream.ReadN(4)
		if err != nil {
			return nil, fmt.Errorf("read JAVA_TC_BLOCKDATALONG object failed on index %v", stream.CurrentIndex())
		}

		// TODO: possibly integer overflow
		length = int(binary.BigEndian.Uint32(lengthBs))
	}

	data, err := stream.ReadN(length)
	if err != nil {
		return nil, fmt.Errorf("read JAVA_TC_BLOCKDATA|JAVA_TC_BLOCKDATALONG object failed on index %v", stream.CurrentIndex())
	}

	return &TCBlockData{
		Data: data,
	}, nil
}
