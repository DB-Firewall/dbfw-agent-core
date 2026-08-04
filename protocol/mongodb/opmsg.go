package mongodb

import (
	"encoding/binary"
	"strings"
)

// CommandInfo holds information extracted from a MongoDB command packet.
type CommandInfo struct {
	Command     string   // e.g. "find", "insert", "drop", "dropDatabase"
	Collection  string   // collection name (value of the command key)
	Database    string   // $db field
	DangerousOps []string // $where, $function, $accumulator found in document
	EmptyFilter bool     // delete/update with no filter (mass operation)
}

// ToRuleString converts command info to a string for regex-based rule matching.
// Format: "CMD:find DB:mydb COLL:users HAS:$where EMPTY_FILTER"
func (c *CommandInfo) ToRuleString() string {
	var b strings.Builder
	b.WriteString("CMD:")
	b.WriteString(c.Command)
	if c.Database != "" {
		b.WriteString(" DB:")
		b.WriteString(c.Database)
	}
	if c.Collection != "" {
		b.WriteString(" COLL:")
		b.WriteString(c.Collection)
	}
	for _, op := range c.DangerousOps {
		b.WriteString(" HAS:")
		b.WriteString(op)
	}
	if c.EmptyFilter {
		b.WriteString(" EMPTY_FILTER")
	}
	return b.String()
}

// ExtractCommand parses a client→server packet and returns the CommandInfo.
// Returns nil, false for server responses or unparseable packets.
func ExtractCommand(pkt *Packet) (*CommandInfo, bool) {
	if !pkt.IsClientMessage() {
		return nil, false
	}
	switch pkt.OpCode {
	case OpMsg:
		return parseOpMsg(pkt.Payload)
	case OpQuery:
		return parseOpQuery(pkt.Payload)
	default:
		return nil, false
	}
}

func parseOpMsg(payload []byte) (*CommandInfo, bool) {
	if len(payload) < 5 {
		return nil, false
	}
	pos := 4 // skip flagBits
	for pos < len(payload) {
		kind := payload[pos]
		pos++
		switch kind {
		case 0: // body section: single BSON document
			if pos+4 > len(payload) {
				return nil, false
			}
			docLen := int(binary.LittleEndian.Uint32(payload[pos:]))
			if docLen < 5 || pos+docLen > len(payload) {
				return nil, false
			}
			return buildInfo(payload[pos : pos+docLen]), true
		case 1: // document sequence: skip
			if pos+4 > len(payload) {
				return nil, false
			}
			seqLen := int(binary.LittleEndian.Uint32(payload[pos:]))
			if seqLen < 4 {
				return nil, false
			}
			pos += seqLen
		default:
			return nil, false
		}
	}
	return nil, false
}

// parseOpQuery handles the legacy OP_QUERY format used by older drivers.
// Layout: flags(4) + fullCollectionName(cstring) + numberToSkip(4) + numberToReturn(4) + query(BSON)
func parseOpQuery(payload []byte) (*CommandInfo, bool) {
	if len(payload) < 9 {
		return nil, false
	}
	pos := 4 // skip flags
	for pos < len(payload) && payload[pos] != 0 {
		pos++
	}
	if pos >= len(payload) {
		return nil, false
	}
	pos += 1 + 8 // skip null terminator + numberToSkip(4) + numberToReturn(4)
	if pos >= len(payload) {
		return nil, false
	}
	return buildInfo(payload[pos:]), true
}

func buildInfo(bsonData []byte) *CommandInfo {
	cmd, coll := FirstKeyValue(bsonData)
	fields := ParseTopLevel(bsonData)
	info := &CommandInfo{
		Command:      cmd,
		Collection:   coll,
		DangerousOps: ScanDangerousOps(bsonData),
	}
	if db, ok := fields["$db"]; ok {
		info.Database = db
	}
	if cmd == "delete" || cmd == "update" {
		info.EmptyFilter = HasEmptyFilter(bsonData)
	}
	return info
}

// BuildBlockResponse constructs an OP_MSG error response for the given requestID.
func BuildBlockResponse(responseTo int32, message string) []byte {
	bsonDoc := buildErrorBSON(message)
	// OP_MSG: flagBits(4) + kind(1) + bsonDoc
	totalLen := int32(16 + 4 + 1 + len(bsonDoc))
	raw := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(raw[4:8], 0)
	binary.LittleEndian.PutUint32(raw[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(raw[12:16], uint32(OpMsg))
	// raw[16:20] = flagBits = 0 (zero-initialized)
	// raw[20] = kind = 0 (body section)
	copy(raw[21:], bsonDoc)
	return raw
}

// buildErrorBSON builds a minimal BSON document: { "ok": 0.0, "errmsg": msg, "code": 2 }
func buildErrorBSON(errmsg string) []byte {
	msgBytes := []byte(errmsg)
	msgBSONLen := int32(len(msgBytes) + 1) // BSON string length includes null terminator
	// doc = 4(docLen) + 12("ok" double) + 13+len("errmsg" string) + 10("code" int32) + 1(term)
	docSize := int32(4 + 12 + (1 + 7 + 4 + len(msgBytes) + 1) + 10 + 1)
	buf := make([]byte, docSize)
	pos := 0
	binary.LittleEndian.PutUint32(buf[pos:], uint32(docSize)); pos += 4
	// "ok": 0.0 (double)
	buf[pos] = 0x01; pos++
	copy(buf[pos:], "ok\x00"); pos += 3
	pos += 8 // 8 zero bytes = IEEE 754 0.0
	// "errmsg": message (string)
	buf[pos] = 0x02; pos++
	copy(buf[pos:], "errmsg\x00"); pos += 7
	binary.LittleEndian.PutUint32(buf[pos:], uint32(msgBSONLen)); pos += 4
	copy(buf[pos:], msgBytes); pos += len(msgBytes)
	buf[pos] = 0x00; pos++
	// "code": 2 (int32)
	buf[pos] = 0x10; pos++
	copy(buf[pos:], "code\x00"); pos += 5
	binary.LittleEndian.PutUint32(buf[pos:], 2); pos += 4
	// document terminator
	buf[pos] = 0x00
	return buf
}
