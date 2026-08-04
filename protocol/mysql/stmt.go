package mysql

import (
	"encoding/binary"
	"sync"
)

// StmtRegistry maps statement IDs to their SQL template for one connection.
// It is safe for concurrent use by the two proxy goroutines.
type StmtRegistry struct {
	mu    sync.Mutex
	stmts map[uint32]string
}

// NewStmtRegistry returns an empty registry.
func NewStmtRegistry() *StmtRegistry {
	return &StmtRegistry{stmts: make(map[uint32]string)}
}

// Register associates stmt_id with its SQL template.
func (r *StmtRegistry) Register(id uint32, sql string) {
	r.mu.Lock()
	r.stmts[id] = sql
	r.mu.Unlock()
}

// Lookup returns the SQL template for stmt_id.
func (r *StmtRegistry) Lookup(id uint32) (string, bool) {
	r.mu.Lock()
	s, ok := r.stmts[id]
	r.mu.Unlock()
	return s, ok
}

// Delete removes a prepared statement (called on COM_STMT_CLOSE).
func (r *StmtRegistry) Delete(id uint32) {
	r.mu.Lock()
	delete(r.stmts, id)
	r.mu.Unlock()
}

// ExtractPrepareSQL returns the SQL text from a COM_STMT_PREPARE payload.
func ExtractPrepareSQL(payload []byte) (string, bool) {
	if len(payload) < 2 || Command(payload[0]) != ComStmtPrepare {
		return "", false
	}
	return string(payload[1:]), true
}

// ParseStmtPrepareOK extracts the statement_id from a COM_STMT_PREPARE_OK
// server response payload. Returns ok=false if the packet is not a valid
// prepare-OK (e.g. it is an error packet).
//
// Wire layout:
//
//	status(1)=0x00 | stmt_id(4 LE) | num_columns(2) | num_params(2) | reserved(1) | warnings(2)
func ParseStmtPrepareOK(payload []byte) (stmtID uint32, ok bool) {
	if len(payload) < 12 || payload[0] != 0x00 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(payload[1:5]), true
}

// ExtractStmtExecuteID returns the statement_id from a COM_STMT_EXECUTE payload.
//
// Wire layout:
//
//	cmd(1)=0x17 | stmt_id(4 LE) | flags(1) | iteration_count(4 LE) | ...
func ExtractStmtExecuteID(payload []byte) (uint32, bool) {
	if len(payload) < 10 || Command(payload[0]) != ComStmtExecute {
		return 0, false
	}
	return binary.LittleEndian.Uint32(payload[1:5]), true
}

// ExtractStmtCloseID returns the statement_id from a COM_STMT_CLOSE payload.
//
// Wire layout:
//
//	cmd(1)=0x19 | stmt_id(4 LE)
func ExtractStmtCloseID(payload []byte) (uint32, bool) {
	if len(payload) < 5 || Command(payload[0]) != ComStmtClose {
		return 0, false
	}
	return binary.LittleEndian.Uint32(payload[1:5]), true
}
