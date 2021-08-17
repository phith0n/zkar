package commons

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"strings"
)

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
	case float32:
		bs = make([]byte, 4)
		binary.BigEndian.PutUint32(bs, math.Float32bits(i))
	case float64:
		bs = make([]byte, 8)
		binary.BigEndian.PutUint64(bs, math.Float64bits(i))
	case int:
		if uintSize == 64 {
			bs = make([]byte, 8)
			binary.BigEndian.PutUint64(bs, uint64(i))
		} else {
			bs = make([]byte, 4)
			binary.BigEndian.PutUint32(bs, uint32(i))
		}
	case uint:
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

func Hexify(data interface{}) string {
	var bs []byte
	switch data := data.(type) {
	case []byte:
		bs = data
	case string:
		bs = []byte(data)
	case byte:
		bs = append(bs, data)
	case int8, int16, uint16, int32, uint32, int64, uint64, int, uint, float32, float64:
		bs = NumberToBytes(data)
	case bool:
		if data {
			bs = []byte{0x01}
		} else {
			bs = []byte{0x00}
		}
	default:
		panic("type error")
	}

	var b = strings.Builder{}
	b.WriteString("0x")
	for _, ch := range bs {
		b.WriteString(hex.EncodeToString([]byte{ch}))
		b.WriteString(" ")
	}

	return strings.TrimSpace(b.String())
}
