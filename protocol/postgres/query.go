package postgres

// PostgreSQL frontend message types (client → server)
const (
	MsgQuery    byte = 'Q' // Simple Query
	MsgParse    byte = 'P' // Extended query: Parse (prepared statement)
	MsgBind     byte = 'B' // Extended query: Bind
	MsgExecute  byte = 'E' // Extended query: Execute
	MsgDescribe byte = 'D' // Describe
	MsgClose    byte = 'C' // Close
	MsgSync     byte = 'S' // Sync
	MsgFlush    byte = 'H' // Flush
	MsgTerminate byte = 'X' // Terminate
)

// PostgreSQL backend message types (server → client)
const (
	MsgReadyForQuery    byte = 'Z'
	MsgAuthRequest      byte = 'R'
	MsgErrorResponse    byte = 'E'
	MsgParameterStatus  byte = 'S'
	MsgBackendKeyData   byte = 'K'
	MsgCommandComplete  byte = 'C'
	MsgRowDescription   byte = 'T'
	MsgDataRow          byte = 'D'
	MsgEmptyQueryResponse byte = 'I'
	MsgNoticeResponse   byte = 'N'
)

// ExtractSQL returns the SQL text from a SimpleQuery ('Q') or Parse ('P') packet.
// Returns "", false if the packet type is not a query or the payload is malformed.
func ExtractSQL(pkt *Packet) (string, bool) {
	switch pkt.Type {
	case MsgQuery:
		// SimpleQuery: null-terminated query string
		if len(pkt.Payload) == 0 {
			return "", false
		}
		sql := pkt.Payload
		if len(sql) > 0 && sql[len(sql)-1] == 0 {
			sql = sql[:len(sql)-1]
		}
		return string(sql), true

	case MsgParse:
		// Parse: statement_name(cstring) + query(cstring) + param_count(int16) + ...
		// Skip the statement name (first cstring)
		pos := 0
		for pos < len(pkt.Payload) && pkt.Payload[pos] != 0 {
			pos++
		}
		pos++ // skip null terminator
		if pos >= len(pkt.Payload) {
			return "", false
		}
		// Query string starts here (cstring)
		end := pos
		for end < len(pkt.Payload) && pkt.Payload[end] != 0 {
			end++
		}
		if end == pos {
			return "", false // empty query (unnamed prepared statement close)
		}
		return string(pkt.Payload[pos:end]), true
	}
	return "", false
}

// cstring reads a null-terminated string from p starting at off, returning the
// string and the offset just past its null terminator.
func cstring(p []byte, off int) (string, int, bool) {
	end := off
	for end < len(p) && p[end] != 0 {
		end++
	}
	if end >= len(p) { // no terminator found
		return "", off, false
	}
	return string(p[off:end]), end + 1, true
}

// ParseParse extracts the prepared-statement name and SQL text from a Parse
// ('P') packet: statement_name(cstring) + query(cstring) + ...
// The unnamed prepared statement has name "".
func ParseParse(pkt *Packet) (name, sql string, ok bool) {
	if pkt.Type != MsgParse {
		return "", "", false
	}
	name, pos, ok := cstring(pkt.Payload, 0)
	if !ok {
		return "", "", false
	}
	sql, _, ok = cstring(pkt.Payload, pos)
	if !ok {
		return "", "", false
	}
	return name, sql, true
}

// ParseBind extracts the portal name and source statement name from a Bind
// ('B') packet: portal_name(cstring) + statement_name(cstring) + ...
// Either name may be "" (unnamed portal / unnamed statement).
func ParseBind(pkt *Packet) (portal, stmt string, ok bool) {
	if pkt.Type != MsgBind {
		return "", "", false
	}
	portal, pos, ok := cstring(pkt.Payload, 0)
	if !ok {
		return "", "", false
	}
	stmt, _, ok = cstring(pkt.Payload, pos)
	if !ok {
		return "", "", false
	}
	return portal, stmt, true
}

// ParseExecute extracts the portal name from an Execute ('E') packet:
// portal_name(cstring) + max_rows(int32). The unnamed portal is "".
func ParseExecute(pkt *Packet) (portal string, ok bool) {
	if pkt.Type != MsgExecute {
		return "", false
	}
	portal, _, ok = cstring(pkt.Payload, 0)
	return portal, ok
}

// ReadyForQueryStatus returns the transaction-status byte of a backend
// ReadyForQuery ('Z') packet: 'I' idle, 'T' in transaction, 'E' failed txn.
func ReadyForQueryStatus(pkt *Packet) (byte, bool) {
	if pkt.Type != MsgReadyForQuery || len(pkt.Payload) < 1 {
		return 0, false
	}
	return pkt.Payload[len(pkt.Payload)-1], true
}
