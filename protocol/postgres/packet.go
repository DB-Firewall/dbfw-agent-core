// Package postgres implements the PostgreSQL frontend/backend wire protocol.
// Reference: https://www.postgresql.org/docs/current/protocol-message-formats.html
package postgres

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Packet is a single PostgreSQL wire-protocol message (frontend or backend).
// Format: Type(1) + Length(4, includes itself) + Payload(Length-4 bytes)
type Packet struct {
	Type    byte
	Length  int32  // value of the length field (includes the 4-byte length itself)
	Payload []byte // Length-4 bytes of data
	Raw     []byte // complete packet: 1 + 4 + (Length-4) bytes
}

// ReadPacket reads one complete PostgreSQL wire-protocol message.
// This must only be called after the startup phase (messages have a type byte).
func ReadPacket(r io.Reader) (*Packet, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	msgLen := int32(binary.BigEndian.Uint32(hdr[1:5]))
	if msgLen < 4 || msgLen > 256*1024*1024 {
		return nil, fmt.Errorf("postgres: invalid message length %d", msgLen)
	}
	payloadLen := msgLen - 4
	raw := make([]byte, 1+msgLen)
	copy(raw[:5], hdr[:])
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, raw[5:]); err != nil {
			return nil, err
		}
	}
	return &Packet{
		Type:    hdr[0],
		Length:  msgLen,
		Payload: raw[5:],
		Raw:     raw,
	}, nil
}

// ReadStartupBytes reads a PostgreSQL startup message (no type byte).
// Returns the raw bytes including the 4-byte length field.
// Used for both SSLRequest and StartupMessage.
func ReadStartupBytes(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	msgLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if msgLen < 4 || msgLen > 10000 {
		return nil, fmt.Errorf("postgres: invalid startup message length %d", msgLen)
	}
	raw := make([]byte, msgLen)
	copy(raw[:4], lenBuf[:])
	if msgLen > 4 {
		if _, err := io.ReadFull(r, raw[4:]); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

// IsSSLRequest returns true if raw is a PostgreSQL SSLRequest message.
func IsSSLRequest(raw []byte) bool {
	return len(raw) == 8 && binary.BigEndian.Uint32(raw[4:8]) == 80877103
}

// BuildErrorResponse builds a PostgreSQL ErrorResponse packet.
// After sending this, the caller must also send ReadyForQueryIdle() so the
// client can recover and send the next query.
func BuildErrorResponse(message string) []byte {
	msgBytes := []byte(message)
	// Body fields: S+ERROR\0 + C+42501\0 + M+msg+\0 + \0
	bodyLen := 7 + 7 + 2 + len(msgBytes) + 1
	// Length field value = 4 + bodyLen; total = 1 + 4 + bodyLen
	totalLen := 1 + 4 + bodyLen
	buf := make([]byte, totalLen)
	buf[0] = 'E'
	binary.BigEndian.PutUint32(buf[1:5], uint32(4+bodyLen))
	pos := 5
	buf[pos] = 'S'; pos++
	copy(buf[pos:], "ERROR\x00"); pos += 6
	buf[pos] = 'C'; pos++
	copy(buf[pos:], "42501\x00"); pos += 6 // insufficient_privilege
	buf[pos] = 'M'; pos++
	copy(buf[pos:], msgBytes); pos += len(msgBytes)
	buf[pos] = 0x00; pos++
	buf[pos] = 0x00 // field list terminator
	return buf
}

// ReadyForQueryIdle returns a ReadyForQuery('I') packet (idle status).
// Must be sent after an ErrorResponse so the client can issue the next query.
func ReadyForQueryIdle() []byte {
	return []byte{'Z', 0, 0, 0, 5, 'I'}
}
