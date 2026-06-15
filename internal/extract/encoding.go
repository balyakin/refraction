package extract

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

func DecodeText(data []byte) (string, bool) {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return strings.ToValidUTF8(string(data[3:]), ""), true
	}
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return decodeUTF16(data[2:], binary.LittleEndian), true
	}
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return decodeUTF16(data[2:], binary.BigEndian), true
	}
	return strings.ToValidUTF8(string(data), ""), false
}

func decodeUTF16(data []byte, order binary.ByteOrder) string {
	if len(data)%2 == 1 {
		data = data[:len(data)-1]
	}
	u16 := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		u16 = append(u16, order.Uint16(data[i:i+2]))
	}
	return string(utf16.Decode(u16))
}

func IsBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return false
	}
	if len(data) >= 2 && ((data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF)) {
		return false
	}
	n := len(data)
	if n > 8192 {
		n = 8192
	}
	nonPrintable := 0
	for _, b := range data[:n] {
		switch {
		case b == 0:
			nonPrintable++
		case b == '\n' || b == '\r' || b == '\t':
		case b >= 0x20 && b < 0x7f:
		case b >= 0x80:
		default:
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(n) > 0.30
}
