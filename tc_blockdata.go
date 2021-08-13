package javaserialize

import (
	"encoding/binary"
	"fmt"
)

type TCBlockData struct {
	data []byte
}

func (bd *TCBlockData) ToBytes() []byte {
	var bs []byte
	if len(bd.data) > 0xFF {
		bs = append(bs, JAVA_TC_BLOCKDATALONG)
		bs = append(bs, NumberToBytes(uint32(len(bd.data)))...)
	} else {
		bs = append(bs, JAVA_TC_BLOCKDATA)
		bs = append(bs, NumberToBytes(uint8(len(bd.data)))...)
	}

	return append(bs, bd.data...)
}

func readTCBlockData(stream *ObjectStream) (*TCBlockData, error) {
	// read JAVA_TC_BLOCKDATA or JAVA_TC_BLOCKDATALONG Flag
	flag, _ := stream.ReadN(1)
	var length int
	if flag[0] == JAVA_TC_BLOCKDATA {
		lengthBs, err := stream.ReadN(1)
		if err != nil {
			sugar.Error(err)
			return nil, fmt.Errorf("read JAVA_TC_BLOCKDATA object failed on index %v", stream.CurrentIndex())
		}

		length = int(lengthBs[0])
	} else {
		lengthBs, err := stream.ReadN(4)
		if err != nil {
			sugar.Error(err)
			return nil, fmt.Errorf("read JAVA_TC_BLOCKDATALONG object failed on index %v", stream.CurrentIndex())
		}

		// TODO: possibly integer overflow
		length = int(binary.BigEndian.Uint32(lengthBs))
	}

	data, err := stream.ReadN(length)
	if err != nil {
		sugar.Error(err)
		return nil, fmt.Errorf("read JAVA_TC_BLOCKDATA|JAVA_TC_BLOCKDATALONG object failed on index %v", stream.CurrentIndex())
	}

	return &TCBlockData{
		data: data,
	}, nil
}
