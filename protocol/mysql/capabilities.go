package mysql

import "encoding/binary"

// Capabilities is the 32-bit MySQL capability flag bitmap exchanged during the
// connection handshake. We only define the flags we act on; the full list is in
// the MySQL protocol documentation.
type Capabilities uint32

const (
	// ClientCompress means the connection switches to the compressed protocol
	// after the handshake, wrapping every packet. We cannot frame that yet.
	ClientCompress Capabilities = 1 << 5 // 0x00000020

	// ClientProtocol41 marks the modern 4.1 handshake layout. Every supported
	// client sets it; we keep it for clarity and future validation.
	ClientProtocol41 Capabilities = 1 << 9 // 0x00000200

	// ClientSSL means the client switches to TLS after sending an SSL request
	// packet. Everything after that is ciphertext and opaque to us.
	ClientSSL Capabilities = 1 << 11 // 0x00000800

	// ClientQueryAttributes means COM_QUERY carries a parameter block between
	// the command byte and the SQL text (MySQL 8.0.23+).
	ClientQueryAttributes Capabilities = 1 << 27 // 0x08000000
)

// Has reports whether every bit in flag is set.
func (c Capabilities) Has(flag Capabilities) bool {
	return c&flag == flag
}

// ClientCapabilitiesFromHandshakeResponse reads the client capability flags
// from the start of a Handshake Response (or SSL Request) packet payload.
//
// In the 4.1 protocol the flags are the first 4 bytes, little-endian. ok is
// false if the payload is too short to contain them.
func ClientCapabilitiesFromHandshakeResponse(payload []byte) (caps Capabilities, ok bool) {
	if len(payload) < 4 {
		return 0, false
	}
	return Capabilities(binary.LittleEndian.Uint32(payload[:4])), true
}
