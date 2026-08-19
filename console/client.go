// Package console provides an HTTP client for communicating with the DBFW
// Management Console: pulling rules, pushing events, and sending heartbeats.
package console

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/DB-Firewall/dbfw-agent-core/engine"
)

// Client talks to the DBFW Management Console.
type Client struct {
	baseURL     string
	secret      string
	agentID     string
	agentName   string
	dbType      string
	agentType   string // "proxy" (inline) or "tap" (passive mirror)
	monitorOnly bool   // tap mode: cannot block, so BLOCK decisions surface as ALERT
	http        *http.Client
	logger      *slog.Logger
}

// New creates a Client. agentID is a stable unique ID for this agent instance.
// If agentID is empty, a random ID is generated (lost on restart — use a fixed value).
func New(baseURL, secret, agentID, agentName, dbType string, logger *slog.Logger) *Client {
	if agentID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		agentID = "proxy-" + hex.EncodeToString(b)
	}
	return &Client{
		baseURL:   baseURL,
		secret:    secret,
		agentID:   agentID,
		agentName: agentName,
		dbType:    dbType,
		agentType: "proxy",
		http:      &http.Client{Timeout: 10 * time.Second},
		logger:    logger,
	}
}

// SetMode overrides the reported agent_type and enables monitor-only semantics.
// In monitor-only (tap) mode a BLOCK decision is reported as ALERT, since a
// passive tap observes traffic but cannot drop it.
func (c *Client) SetMode(agentType string, monitorOnly bool) {
	if agentType != "" {
		c.agentType = agentType
	}
	c.monitorOnly = monitorOnly
}

// Start runs background goroutines:
//   - Polls rules from the console every pollInterval and reloads the engine.
//   - Sends a heartbeat every 30s.
//
// Call this in a goroutine; it blocks until ctx is cancelled.
func (c *Client) Start(ctx context.Context, eng *engine.Engine, pollInterval time.Duration) {
	if pollInterval <= 0 {
		pollInterval = 60 * time.Second
	}

	// Immediate first poll
	if rules, err := c.fetchRules(); err == nil {
		eng.Reload(rules)
		c.logger.Info("console rules loaded", "count", len(rules))
	} else {
		c.logger.Warn("initial rule fetch failed", "err", err)
	}
	c.sendHeartbeat()

	ruleTick := time.NewTicker(pollInterval)
	hbTick := time.NewTicker(30 * time.Second)
	defer ruleTick.Stop()
	defer hbTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ruleTick.C:
			if rules, err := c.fetchRules(); err == nil {
				eng.Reload(rules)
				c.logger.Info("rules reloaded", "count", len(rules))
			} else {
				c.logger.Warn("rule poll failed", "err", err)
			}
		case <-hbTick.C:
			c.sendHeartbeat()
		}
	}
}

// Sink returns an engine.EventSink that forwards all query events to the console.
// BLOCK → "BLOCK", ALERT → "ALERT", ALLOW → "INFO".
func (c *Client) Sink() engine.EventSink {
	return func(action engine.Action, ruleName, sql string, meta engine.QueryMeta) {
		var level string
		switch action {
		case engine.ActionBlock:
			if c.monitorOnly {
				level = "ALERT" // passive tap cannot block
			} else {
				level = "BLOCK"
			}
		case engine.ActionAlert:
			level = "ALERT"
		default:
			level = "INFO"
		}
		appIP, srcPort := splitHostPort(meta.Source)
		ev := map[string]any{
			"level":      level,
			"agent_type": c.agentType,
			"db_type":    c.dbType,
			"rule":       ruleName,
			"source":     meta.Source,
			"query":      sql,
			// ── correlation context (HPTR) ──
			"app_ip":     appIP,
			"src_port":   srcPort,
			"conn_id":    meta.ConnID,
			"seq":        meta.Seq,
			"txn_status": meta.TxnStatus,
		}
		// CDFC: result-set fingerprint tokens (only when present).
		if len(meta.Tokens) > 0 {
			ev["tokens"] = meta.Tokens
		}
		// CDFC forensics: bounded readable render of the result rows.
		if meta.Result != "" {
			ev["result"] = meta.Result
		}
		// Carry the agent-side execution timestamp so the console does not
		// overwrite it with its (jittered) receive time — load-bearing for
		// sub-second causal-window correlation.
		if !meta.EventTime.IsZero() {
			ev["time"] = meta.EventTime.UTC().Format(time.RFC3339Nano)
		}
		go c.pushEvent(ev) // non-blocking hot-path
	}
}

// splitHostPort splits "ip:port" into its host and port parts, tolerating an
// address with no port (returns the whole string as host).
func splitHostPort(addr string) (host, port string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return addr, ""
}

// ─── Internal ────────────────────────────────────────────────────────────────

// apiRule mirrors the JSON shape returned by GET /api/agent/rules.
type apiRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	DBType  string `json:"db_type"`
	Pattern string `json:"pattern"`
	Action  string `json:"action"`
	Enabled bool   `json:"enabled"`
}

func (c *Client) fetchRules() ([]*engine.Rule, error) {
	url := fmt.Sprintf("%s/api/agent/rules?db_type=%s", c.baseURL, c.dbType)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.secret != "" {
		req.Header.Set("X-DBFW-Secret", c.secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("console returned %d", resp.StatusCode)
	}
	var apiRules []apiRule
	if err := json.NewDecoder(resp.Body).Decode(&apiRules); err != nil {
		return nil, err
	}
	return convertRules(apiRules), nil
}

func (c *Client) pushEvent(ev map[string]any) {
	body, _ := json.Marshal(ev)
	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/events/ingest", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DBFW-Agent-ID", c.agentID)
	if c.secret != "" {
		req.Header.Set("X-DBFW-Secret", c.secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.logger.Debug("event push failed", "err", err)
		return
	}
	resp.Body.Close()
}

func (c *Client) sendHeartbeat() {
	hb := map[string]any{
		"id":         c.agentID,
		"name":       c.agentName,
		"agent_type": c.agentType,
		"db_type":    c.dbType,
		"version":    "1.0.0",
	}
	body, _ := json.Marshal(hb)
	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/agent/heartbeat", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if c.secret != "" {
		req.Header.Set("X-DBFW-Secret", c.secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.logger.Debug("heartbeat failed", "err", err)
		return
	}
	resp.Body.Close()
}

// convertRules converts Console API rules to engine.Rule objects.
func convertRules(apiRules []apiRule) []*engine.Rule {
	var out []*engine.Rule
	for _, ar := range apiRules {
		if !ar.Enabled {
			continue
		}
		r := &engine.Rule{
			Name:   ar.Name,
			Action: engine.Action(strings.ToLower(ar.Action)),
		}
		if ar.Pattern != "" {
			re, err := regexp.Compile(ar.Pattern)
			if err == nil {
				r.SQLPattern = re
			}
		}
		out = append(out, r)
	}
	return out
}
