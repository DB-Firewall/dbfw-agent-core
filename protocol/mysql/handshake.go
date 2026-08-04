package mysql

import (
	"bytes"
	"encoding/binary"
)

// Additional capability flags needed for full handshake parsing.
const (
	ClientConnectWithDB              Capabilities = 1 << 3  // 0x00000008
	ClientSecureConnection           Capabilities = 1 << 15 // 0x00008000
	ClientPluginAuthLenencClientData Capabilities = 1 << 21 // 0x00200000
	ClientPluginAuth                 Capabilities = 1 << 19 // 0x00080000
)

// HandshakeInfo holds client identity fields extracted from a HandshakeResponse41.
type HandshakeInfo struct {
	Caps     Capabilities
	Username string
	Database string // empty when CLIENT_CONNECT_WITH_DB is not set
}

// ParseHandshakeResponse parses a HandshakeResponse41 payload and returns the
// identity fields. ok=false on truncated or malformed input.
//
// Wire layout (Protocol 4.1):
//
//	caps(4) | max_packet_size(4) | charset(1) | reserved(23)
//	username (NUL-terminated)
//	auth_response (length-encoded or fixed, depending on caps)
//	database (NUL-terminated, only when CLIENT_CONNECT_WITH_DB is set)
//	auth_plugin_name (NUL-terminated, only when CLIENT_PLUGIN_AUTH is set)
func ParseHandshakeResponse(payload []byte) (info HandshakeInfo, ok bool) {
	// Fixed header: caps(4) + max_packet_size(4) + charset(1) + reserved(23) = 32 bytes
	if len(payload) < 32 {
		return info, false
	}
	info.Caps = Capabilities(binary.LittleEndian.Uint32(payload[:4]))

	// An SSL Request packet is exactly 32 bytes: capability_flags(4) +
	// max_packet_size(4) + charset(1) + reserved(23). There is no username.
	// Return ok=true so the caller can detect ClientSSL and disable inspection.
	if len(payload) == 32 {
		return info, true
	}

	pos := 32

	// Username: NUL-terminated string
	end := bytes.IndexByte(payload[pos:], 0)
	if end < 0 {
		return info, false
	}
	info.Username = string(payload[pos : pos+end])
	pos += end + 1

	// Auth response: length encoding depends on negotiated capabilities
	if info.Caps.Has(ClientPluginAuthLenencClientData) {
		authLen, n, ok2 := readLenEncInt(payload[pos:])
		if !ok2 {
			return info, false
		}
		pos += n + int(authLen)
	} else if info.Caps.Has(ClientSecureConnection) {
		if pos >= len(payload) {
			return info, false
		}
		authLen := int(payload[pos])
		pos += 1 + authLen
	} else {
		// Legacy: NUL-terminated auth data
		end = bytes.IndexByte(payload[pos:], 0)
		if end < 0 {
			pos = len(payload)
		} else {
			pos += end + 1
		}
	}

	// Database name: only present when CLIENT_CONNECT_WITH_DB is set
	if info.Caps.Has(ClientConnectWithDB) && pos < len(payload) {
		end = bytes.IndexByte(payload[pos:], 0)
		if end >= 0 {
			info.Database = string(payload[pos : pos+end])
		} else {
			info.Database = string(payload[pos:])
		}
	}

	return info, true
}
