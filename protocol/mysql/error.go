package mysql

// BuildErrorPacket constructs a MySQL ERR_Packet ready to write directly to a
// client connection. seq should be the command's sequence number + 1 (the
// server always responds with the client's seq incremented by one).
//
// Wire layout (Protocol 4.1):
//
//	header(4): payload_length(3 LE) + sequence_id(1)
//	0xFF                       error marker
//	error_code(2 LE)           MySQL error number
//	'#'(1)                     SQL state marker (CLIENT_PROTOCOL_41)
//	sql_state(5)               SQLSTATE value, e.g. "42000"
//	error_message(variable)    human-readable text
func BuildErrorPacket(seq uint8, code uint16, sqlState, message string) []byte {
	// payload = 0xFF(1) + code(2) + '#'(1) + sqlState(5) + message
	payload := make([]byte, 0, 9+len(message))
	payload = append(payload, 0xFF)
	payload = append(payload, byte(code), byte(code>>8))
	payload = append(payload, '#')

	var state [5]byte
	copy(state[:], sqlState) // zero-pads if sqlState is shorter than 5
	payload = append(payload, state[:]...)
	payload = append(payload, message...)

	// 4-byte header
	pktLen := len(payload)
	pkt := make([]byte, 4+pktLen)
	pkt[0] = byte(pktLen)
	pkt[1] = byte(pktLen >> 8)
	pkt[2] = byte(pktLen >> 16)
	pkt[3] = seq
	copy(pkt[4:], payload)
	return pkt
}
