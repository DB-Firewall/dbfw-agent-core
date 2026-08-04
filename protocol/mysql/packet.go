// Package mysql parses the MySQL client/server wire protocol.
//
// Phase 1 scope: frame packets off the byte stream, identify command-phase
// packet types, and extract SQL text from COM_QUERY. We never alter the stream
// here - the proxy forwards the original bytes verbatim and only inspects.
package mysql

import (
	"fmt"
	"io"
)

const (
	// HeaderLen is the size of a MySQL packet header: a 3-byte little-endian
	// payload length followed by a 1-byte sequence number.
	HeaderLen = 4

	// MaxPayloadLen is the largest payload a single wire packet can carry
	// (2^24 - 1). A fragment of exactly this size means the logical packet
	// continues in the next fragment, terminated by a fragment that is shorter
	// (possibly empty).
	MaxPayloadLen = 1<<24 - 1
)

// Packet is one logical MySQL protocol packet.
//
// For payloads larger than MaxPayloadLen the protocol splits them across
// several wire fragments; Payload holds the reassembled body and Seq is the
// sequence number of the final fragment.
type Packet struct {
	// Seq is the sequence number from the (last) fragment header.
	Seq uint8

	// Payload is the reassembled packet body with all wire headers removed.
	// For single-fragment packets this aliases the body region of Raw.
	Payload []byte

	// Raw is the exact bytes read off the wire - every fragment header and
	// body, in order. Forward these verbatim so we never alter the protocol
	// stream (a re-framing bug in a firewall is a parser-differential bug).
	Raw []byte
}

// Reader frames MySQL packets off an underlying stream (a client or backend
// connection). It holds no buffered payload bytes between calls, so callers may
// safely switch to a plain io.Copy on the same connection after a successful
// ReadPacket.
type Reader struct {
	r   io.Reader
	hdr [HeaderLen]byte
}

// NewReader returns a Reader that frames packets off r.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: r}
}

// ReadPacket reads one logical packet, reassembling multi-fragment payloads.
//
// A clean end of stream surfaces as io.EOF from the first header read; callers
// use that to detect a closed connection. A truncated packet surfaces as
// io.ErrUnexpectedEOF (wrapped).
func (pr *Reader) ReadPacket() (*Packet, error) {
	raw, payload, seq, more, err := pr.readFragment()
	if err != nil {
		return nil, err
	}
	if !more {
		return &Packet{Seq: seq, Payload: payload, Raw: raw}, nil
	}

	// Multi-fragment payload. Copy into growable buffers because the remaining
	// fragments reuse pr.hdr and overwrite the fragment-local backing array.
	rawBuf := append([]byte(nil), raw...)
	payloadBuf := append([]byte(nil), payload...)
	lastSeq := seq
	for more {
		raw, payload, seq, more, err = pr.readFragment()
		if err != nil {
			return nil, fmt.Errorf("read packet continuation: %w", err)
		}
		rawBuf = append(rawBuf, raw...)
		payloadBuf = append(payloadBuf, payload...)
		lastSeq = seq
	}
	return &Packet{Seq: lastSeq, Payload: payloadBuf, Raw: rawBuf}, nil
}

// readFragment reads exactly one wire packet: a 4-byte header plus its body.
// more reports whether the body length was MaxPayloadLen, i.e. the logical
// packet continues in the following fragment. The returned payload aliases the
// body region of raw.
func (pr *Reader) readFragment() (raw, payload []byte, seq uint8, more bool, err error) {
	if _, err = io.ReadFull(pr.r, pr.hdr[:]); err != nil {
		// 0 bytes -> io.EOF (clean close); partial -> io.ErrUnexpectedEOF.
		return nil, nil, 0, false, err
	}
	length := int(pr.hdr[0]) | int(pr.hdr[1])<<8 | int(pr.hdr[2])<<16
	seq = pr.hdr[3]

	raw = make([]byte, HeaderLen+length)
	copy(raw, pr.hdr[:])
	if _, err = io.ReadFull(pr.r, raw[HeaderLen:]); err != nil {
		return nil, nil, 0, false, fmt.Errorf("read payload (%d bytes): %w", length, err)
	}
	return raw, raw[HeaderLen:], seq, length == MaxPayloadLen, nil
}
