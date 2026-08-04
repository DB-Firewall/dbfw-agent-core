package mongodb

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MongoDB wire protocol opCodes
const (
	OpReply  int32 = 1
	OpQuery  int32 = 2004
	OpMsg    int32 = 2013
	OpUpdate int32 = 2001
	OpInsert int32 = 2002
	OpDelete int32 = 2006
)

// Packet is a single MongoDB wire-protocol message.
type Packet struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        int32
	Payload       []byte // everything after the 16-byte header
	Raw           []byte // full packet including header
}

// IsClientMessage returns true for client→server packets (ResponseTo == 0).
func (p *Packet) IsClientMessage() bool {
	return p.ResponseTo == 0
}

// ReadPacket reads one complete MongoDB wire-protocol message.
func ReadPacket(r io.Reader) (*Packet, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	msgLen := int32(binary.LittleEndian.Uint32(hdr[0:4]))
	if msgLen < 16 || msgLen > 48*1024*1024 {
		return nil, fmt.Errorf("mongodb: invalid message length %d", msgLen)
	}
	raw := make([]byte, msgLen)
	copy(raw[:16], hdr[:])
	if msgLen > 16 {
		if _, err := io.ReadFull(r, raw[16:]); err != nil {
			return nil, err
		}
	}
	return &Packet{
		MessageLength: msgLen,
		RequestID:     int32(binary.LittleEndian.Uint32(hdr[4:8])),
		ResponseTo:    int32(binary.LittleEndian.Uint32(hdr[8:12])),
		OpCode:        int32(binary.LittleEndian.Uint32(hdr[12:16])),
		Payload:       raw[16:],
		Raw:           raw,
	}, nil
}
