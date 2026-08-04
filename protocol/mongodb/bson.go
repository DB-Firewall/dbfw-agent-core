package mongodb

import (
	"bytes"
	"encoding/binary"
)

// BSON element type constants
const (
	bsonDouble    byte = 0x01
	bsonString    byte = 0x02
	bsonDocument  byte = 0x03
	bsonArray     byte = 0x04
	bsonBinary    byte = 0x05
	bsonObjectID  byte = 0x07
	bsonBool      byte = 0x08
	bsonDatetime  byte = 0x09
	bsonNull      byte = 0x0A
	bsonRegex     byte = 0x0B
	bsonInt32     byte = 0x10
	bsonTimestamp byte = 0x11
	bsonInt64     byte = 0x12
	bsonDecimal   byte = 0x13
	bsonMinKey    byte = 0xFF
	bsonMaxKey    byte = 0x7F
)

// ParseTopLevel returns top-level string fields from a BSON document.
// Non-string values are skipped.
func ParseTopLevel(data []byte) map[string]string {
	result := make(map[string]string)
	if len(data) < 5 {
		return result
	}
	docLen := int(binary.LittleEndian.Uint32(data[:4]))
	if docLen > len(data) || docLen < 5 {
		return result
	}
	pos := 4
	for pos < docLen-1 && pos < len(data) {
		typ := data[pos]
		pos++
		if typ == 0 {
			break
		}
		keyEnd := pos
		for keyEnd < len(data) && data[keyEnd] != 0 {
			keyEnd++
		}
		if keyEnd >= len(data) {
			break
		}
		key := string(data[pos:keyEnd])
		pos = keyEnd + 1

		advance := skipBSONValue(data, pos, typ)
		if advance < 0 {
			break
		}
		if typ == bsonString && pos+4 <= len(data) {
			strLen := int(binary.LittleEndian.Uint32(data[pos:]))
			end := pos + 4 + strLen
			if end <= len(data) && strLen > 0 {
				result[key] = string(data[pos+4 : end-1])
			}
		}
		pos += advance
	}
	return result
}

// FirstKeyValue returns the key and string value of the first BSON element.
// In MongoDB command documents, this is the command name and collection name.
func FirstKeyValue(data []byte) (key, val string) {
	if len(data) < 5 {
		return
	}
	docLen := int(binary.LittleEndian.Uint32(data[:4]))
	if docLen > len(data) || docLen < 5 {
		return
	}
	pos := 4
	if pos >= len(data) {
		return
	}
	typ := data[pos]
	pos++
	if typ == 0 {
		return
	}
	keyEnd := pos
	for keyEnd < len(data) && data[keyEnd] != 0 {
		keyEnd++
	}
	if keyEnd >= len(data) {
		return
	}
	key = string(data[pos:keyEnd])
	pos = keyEnd + 1
	if typ == bsonString && pos+4 <= len(data) {
		strLen := int(binary.LittleEndian.Uint32(data[pos:]))
		end := pos + 4 + strLen
		if end <= len(data) && strLen > 0 {
			val = string(data[pos+4 : end-1])
		}
	}
	return
}

var dangerousOps = [][]byte{
	[]byte("$where"),
	[]byte("$function"),
	[]byte("$accumulator"),
}

// ScanDangerousOps returns any dangerous MongoDB operators found in the raw BSON bytes.
func ScanDangerousOps(data []byte) []string {
	var found []string
	for _, op := range dangerousOps {
		if bytes.Contains(data, op) {
			found = append(found, string(op))
		}
	}
	return found
}

// HasEmptyFilter returns true if an empty BSON document {} appears in the data.
// Used to detect mass-delete / mass-update operations with no filter.
func HasEmptyFilter(data []byte) bool {
	return bytes.Contains(data, []byte{0x05, 0x00, 0x00, 0x00, 0x00})
}

func skipBSONValue(data []byte, pos int, typ byte) int {
	switch typ {
	case bsonDouble:
		return 8
	case bsonString:
		if pos+4 > len(data) {
			return -1
		}
		return 4 + int(binary.LittleEndian.Uint32(data[pos:]))
	case bsonDocument, bsonArray:
		if pos+4 > len(data) {
			return -1
		}
		return int(binary.LittleEndian.Uint32(data[pos:]))
	case bsonBinary:
		if pos+4 > len(data) {
			return -1
		}
		return 4 + 1 + int(binary.LittleEndian.Uint32(data[pos:]))
	case bsonObjectID:
		return 12
	case bsonBool:
		return 1
	case bsonDatetime, bsonInt64, bsonTimestamp:
		return 8
	case bsonNull, bsonMinKey, bsonMaxKey:
		return 0
	case bsonInt32:
		return 4
	case bsonDecimal:
		return 16
	case bsonRegex:
		p := pos
		for p < len(data) && data[p] != 0 {
			p++
		}
		p++
		for p < len(data) && data[p] != 0 {
			p++
		}
		p++
		return p - pos
	default:
		return -1
	}
}
