package javaserialize

import "encoding/binary"

const uintSize = 32 << (^uint(0) >> 32 & 1) // 32 or 64

func NumberToBytes(data interface{}) []byte {
	var bs []byte
	switch i := data.(type) {
	case int8:
		bs = make([]byte, 1)
		bs[0] = uint8(i)
	case uint8:
		bs = make([]byte, 1)
		bs[0] = i
	case uint16:
		bs = make([]byte, 2)
		binary.BigEndian.PutUint16(bs, i)
	case int16:
		bs = make([]byte, 2)
		binary.BigEndian.PutUint16(bs, uint16(i))
	case int32:
		bs = make([]byte, 4)
		binary.BigEndian.PutUint32(bs, uint32(i))
	case uint32:
		bs = make([]byte, 4)
		binary.BigEndian.PutUint32(bs, i)
	case uint64:
		bs = make([]byte, 8)
		binary.BigEndian.PutUint64(bs, i)
	case int64:
		bs = make([]byte, 8)
		binary.BigEndian.PutUint64(bs, uint64(i))
	case int:
		if uintSize == 64 {
			bs = make([]byte, 8)
			binary.BigEndian.PutUint64(bs, uint64(i))
		} else {
			bs = make([]byte, 4)
			binary.BigEndian.PutUint32(bs, uint32(i))
		}
	default:
		panic("type error")
	}

	return bs
}
