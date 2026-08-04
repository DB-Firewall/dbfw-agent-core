// Package backend handles the connection from our proxy to the real database.
//
// In Phase 1 (this code) we just open a TCP connection and pipe bytes through.
// In Phase 2 we'll add connection pooling and per-query forwarding.
package backend

import (
	"fmt"
	"net"
	"time"
)

// Config holds where the real database is.
type Config struct {
	// Addr is the address of the real database, e.g. "127.0.0.1:3306".
	Addr string

	// DialTimeout is how long we'll wait when opening a connection.
	DialTimeout time.Duration
}

// DefaultConfig returns sensible defaults for local MySQL.
func DefaultConfig() Config {
	return Config{
		Addr:        "127.0.0.1:3306",
		DialTimeout: 5 * time.Second,
	}
}

// Dial opens a fresh TCP connection to the real database.
// One call per client connection - we don't pool yet.
func Dial(cfg Config) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", cfg.Addr, cfg.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial backend %s: %w", cfg.Addr, err)
	}
	return conn, nil
}
