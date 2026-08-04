package mysql

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// comQueryPacket builds the wire bytes for a single COM_QUERY packet carrying
// sql, with the given sequence number.
func comQueryPacket(seq uint8, sql string) []byte {
	payload := append([]byte{byte(ComQuery)}, sql...)
	hdr := []byte{
		byte(len(payload)),
		byte(len(payload) >> 8),
		byte(len(payload) >> 16),
		seq,
	}
	return append(hdr, payload...)
}

func TestReadPacket_Single(t *testing.T) {
	wire := comQueryPacket(0, "SELECT 1")

	pkt, err := NewReader(bytes.NewReader(wire)).ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if pkt.Seq != 0 {
		t.Errorf("Seq = %d, want 0", pkt.Seq)
	}
	if !bytes.Equal(pkt.Raw, wire) {
		t.Errorf("Raw = % x, want % x (must forward verbatim)", pkt.Raw, wire)
	}
	wantPayload := append([]byte{byte(ComQuery)}, "SELECT 1"...)
	if !bytes.Equal(pkt.Payload, wantPayload) {
		t.Errorf("Payload = % x, want % x", pkt.Payload, wantPayload)
	}
}

func TestReadPacket_SeqPreserved(t *testing.T) {
	pkt, err := NewReader(bytes.NewReader(comQueryPacket(7, "x"))).ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if pkt.Seq != 7 {
		t.Errorf("Seq = %d, want 7", pkt.Seq)
	}
}

func TestReadPacket_MultiFragment(t *testing.T) {
	// A first fragment of exactly MaxPayloadLen signals continuation; the
	// second (shorter) fragment terminates the logical packet.
	frag1Body := bytes.Repeat([]byte{0xab}, MaxPayloadLen)
	frag2Body := []byte{0x01, 0x02, 0x03}

	var wire bytes.Buffer
	wire.Write([]byte{0xff, 0xff, 0xff, 0}) // length = MaxPayloadLen, seq 0
	wire.Write(frag1Body)
	wire.Write([]byte{0x03, 0x00, 0x00, 1}) // length = 3, seq 1
	wire.Write(frag2Body)

	pkt, err := NewReader(bytes.NewReader(wire.Bytes())).ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if got, want := len(pkt.Payload), MaxPayloadLen+len(frag2Body); got != want {
		t.Fatalf("reassembled payload len = %d, want %d", got, want)
	}
	if got, want := len(pkt.Raw), wire.Len(); got != want {
		t.Errorf("Raw len = %d, want %d (headers + bodies of every fragment)", got, want)
	}
	if pkt.Seq != 1 {
		t.Errorf("Seq = %d, want 1 (last fragment)", pkt.Seq)
	}
	if !bytes.Equal(pkt.Payload[MaxPayloadLen:], frag2Body) {
		t.Errorf("tail of payload = % x, want % x", pkt.Payload[MaxPayloadLen:], frag2Body)
	}
}

func TestReadPacket_EmptyPayload(t *testing.T) {
	pkt, err := NewReader(bytes.NewReader([]byte{0, 0, 0, 0})).ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if len(pkt.Payload) != 0 {
		t.Errorf("Payload len = %d, want 0", len(pkt.Payload))
	}
}

func TestReadPacket_CleanEOF(t *testing.T) {
	_, err := NewReader(bytes.NewReader(nil)).ReadPacket()
	if !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want io.EOF on a closed stream", err)
	}
}

func TestReadPacket_TruncatedPayload(t *testing.T) {
	// Header claims 5 payload bytes but only 2 are present.
	wire := []byte{0x05, 0x00, 0x00, 0x00, 0x41, 0x42}
	_, err := NewReader(bytes.NewReader(wire)).ReadPacket()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want io.ErrUnexpectedEOF on truncation", err)
	}
}

func TestReadPacket_Sequential(t *testing.T) {
	// Two packets back to back must be framed independently.
	var wire bytes.Buffer
	wire.Write(comQueryPacket(0, "SELECT 1"))
	wire.Write(comQueryPacket(0, "SELECT 2"))

	r := NewReader(bytes.NewReader(wire.Bytes()))
	for _, want := range []string{"SELECT 1", "SELECT 2"} {
		pkt, err := r.ReadPacket()
		if err != nil {
			t.Fatalf("ReadPacket: %v", err)
		}
		if got := string(pkt.Payload[1:]); got != want {
			t.Errorf("query = %q, want %q", got, want)
		}
	}
}
