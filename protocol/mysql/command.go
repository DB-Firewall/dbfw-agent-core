package mysql

import (
	"encoding/binary"
	"fmt"
)

// Command is the first payload byte of a command-phase packet. It identifies
// what the client is asking the server to do.
type Command byte

// The command types we recognise. COM_QUERY is the one Phase 1 cares about; the
// rest are named so logs are readable and so the decision engine can branch on
// them later.
const (
	ComQuit        Command = 0x01
	ComInitDB      Command = 0x02
	ComQuery       Command = 0x03
	ComFieldList   Command = 0x04
	ComCreateDB    Command = 0x05
	ComDropDB      Command = 0x06
	ComPing        Command = 0x0e
	ComStmtPrepare Command = 0x16
	ComStmtExecute Command = 0x17
	ComStmtClose   Command = 0x19
)

// String returns the protocol name of the command, or COM_UNKNOWN(0xNN) for
// command bytes we do not name yet.
func (c Command) String() string {
	switch c {
	case ComQuit:
		return "COM_QUIT"
	case ComInitDB:
		return "COM_INIT_DB"
	case ComQuery:
		return "COM_QUERY"
	case ComFieldList:
		return "COM_FIELD_LIST"
	case ComCreateDB:
		return "COM_CREATE_DB"
	case ComDropDB:
		return "COM_DROP_DB"
	case ComPing:
		return "COM_PING"
	case ComStmtPrepare:
		return "COM_STMT_PREPARE"
	case ComStmtExecute:
		return "COM_STMT_EXECUTE"
	case ComStmtClose:
		return "COM_STMT_CLOSE"
	default:
		return fmt.Sprintf("COM_UNKNOWN(0x%02x)", byte(c))
	}
}

// ExtractQuery returns the SQL text from a COM_QUERY packet payload.
//
// payload[0] is the command byte (0x03). Classic layout: the query string fills
// the rest of the payload. When the connection negotiated
// CLIENT_QUERY_ATTRIBUTES (queryAttrs=true) a parameter block precedes the
// query: parameter_count and parameter_set_count length-encoded integers, then
// - only when parameter_count > 0 - a null bitmap, a bind flag, and binary
// parameter values. We skip the no-parameter case; with parameters present we
// cannot yet locate the query boundary (that needs binary-protocol value
// decoding), so ok is false and the caller should log that the text is
// unavailable rather than emit garbage.
func ExtractQuery(payload []byte, queryAttrs bool) (sql string, ok bool) {
	if len(payload) == 0 || Command(payload[0]) != ComQuery {
		return "", false
	}
	body := payload[1:]

	if !queryAttrs {
		return string(body), true
	}

	paramCount, n1, ok := readLenEncInt(body)
	if !ok {
		return "", false
	}
	body = body[n1:]

	_, n2, ok := readLenEncInt(body) // parameter_set_count, always 1
	if !ok {
		return "", false
	}
	body = body[n2:]

	if paramCount > 0 {
		return "", false
	}
	return string(body), true
}

// readLenEncInt decodes a MySQL length-encoded integer. It returns the value,
// the number of bytes consumed, and whether decoding succeeded. 0xff is not a
// valid prefix here (it marks an ERR/NULL sentinel elsewhere in the protocol).
func readLenEncInt(b []byte) (value uint64, n int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	switch first := b[0]; {
	case first < 0xfb:
		return uint64(first), 1, true
	case first == 0xfc:
		if len(b) < 3 {
			return 0, 0, false
		}
		return uint64(binary.LittleEndian.Uint16(b[1:3])), 3, true
	case first == 0xfd:
		if len(b) < 4 {
			return 0, 0, false
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4, true
	case first == 0xfe:
		if len(b) < 9 {
			return 0, 0, false
		}
		return binary.LittleEndian.Uint64(b[1:9]), 9, true
	default:
		return 0, 0, false
	}
}
