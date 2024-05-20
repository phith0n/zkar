package classfile

import (
	"fmt"
	"unicode/utf16"
)

/*
CONSTANT_Utf8_info {
    u1 tag;
    u2 length;
    u1 bytes[length];
}
*/

type ConstantUtf8Info struct {
	str string
}

func (c *ConstantUtf8Info) readInfo(reader *ClassReader) {
	length := uint32(reader.readUint16())
	bytes := reader.readBytes(length)
	c.str = decodeMUTF8(bytes)
}

func (c *ConstantUtf8Info) Str() string {
	return c.str
}

func decodeMUTF8(byteArr []byte) string {
	utfLen := len(byteArr)
	charArr := make([]uint16, utfLen)
	var c, char2, char3 uint16
	count := 0
	charArrCount := 0
	for count < utfLen {
		c = uint16(byteArr[count])
		if c > 127 {
			break
		}
		count++
		charArr[charArrCount] = c
		charArrCount++
	}
	for count < utfLen {
		c = uint16(byteArr[count])
		switch c >> 4 {
		case 0, 1, 2, 3, 4, 5, 6, 7:
			count++
			charArr[charArrCount] = c
			charArrCount++
		case 12, 13:
			count += 2
			if count > utfLen {
				panic("malformed input: partial character at end")
			}
			char2 = uint16(byteArr[count-1])
			if char2&0xC0 != 0x80 {
				panic(fmt.Errorf("malformed input around byte %v", count))
			}
			charArr[charArrCount] = c&0x1F<<6 | char2&0x3F
			charArrCount++
		case 14:
			count += 3
			if count > utfLen {
				panic("malformed input: partial character at end")
			}
			char2 = uint16(byteArr[count-2])
			char3 = uint16(byteArr[count-1])
			if char2&0xC0 != 0x80 || char3&0xC0 != 0x80 {
				panic(fmt.Errorf("malformed input around byte %v", count-1))
			}
			charArr[charArrCount] = c&0x0F<<12 | char2&0x3F<<6 | char3&0x3F<<0
			charArrCount++
		default:
			panic(fmt.Errorf("malformed input around byte %v", count))
		}
	}
	charArr = charArr[0:charArrCount]
	runes := utf16.Decode(charArr)
	return string(runes)
}
