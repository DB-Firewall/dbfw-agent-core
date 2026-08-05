// Package engine evaluates SQL queries against an ordered set of rules and
// returns a decision: allow, alert, or block.
package engine

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// Action is the verdict a rule produces for a matching query.
type Action string

const (
	ActionAllow  Action = "allow"
	ActionIgnore Action = "ignore" // pass through silently — no event sent to console
	ActionAlert  Action = "alert"  // log and pass through
	ActionBlock  Action = "block"  // send error to client, drop the query
)

// Decision is the result of evaluating a query against the rule set.
type Decision struct {
	Action Action
	Rule   string // name of the matching rule, or "default-allow"
}

// Rule matches queries by SQL pattern and optional user/database filters,
// then assigns them an Action.
type Rule struct {
	Name       string
	Action     Action
	SQLPattern *regexp.Regexp // nil = match any SQL
	Users      []string       // empty = all users
	Databases  []string       // empty = all databases
}

func (r *Rule) matches(sql, username, database string) bool {
	if len(r.Users) > 0 {
		found := false
		for _, u := range r.Users {
			if strings.EqualFold(u, username) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(r.Databases) > 0 {
		found := false
		for _, d := range r.Databases {
			if strings.EqualFold(d, database) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.SQLPattern != nil {
		return r.SQLPattern.MatchString(sql)
	}
	return true
}

// QueryMeta carries per-query connection context captured at the proxy, used by
// the event sink to enable HTTP↔SQL correlation in the console.
type QueryMeta struct {
	Source    string    // app side address as ip:port (raw RemoteAddr)
	ConnID    uint64    // proxy connection id (one app pool slot = one stable ConnID)
	EventTime time.Time // wall-clock instant the query was observed at the proxy
	Seq       uint64    // per-connection monotonic sequence (orders equal-ms queries)
	TxnStatus string    // postgres ReadyForQuery status at send time (I/T/E); "" if N/A
	Tokens    []string  // CDFC: keyed-hash fingerprint of the query's result set ("class:hex")
}

// EventSink is called after every decision (ALLOW, ALERT, BLOCK).
// It runs in the hot path; implementations must be non-blocking.
type EventSink func(action Action, ruleName, sql string, meta QueryMeta)

// Engine evaluates SQL queries against an ordered rule list.
type Engine struct {
	mu    sync.RWMutex
	rules []*Rule
	sink  EventSink
}

// New returns an Engine with the given rules.
func New(rules []*Rule) *Engine {
	return &Engine{rules: rules}
}

// SetSink registers a callback invoked after each decision (ALLOW, ALERT, BLOCK).
func (e *Engine) SetSink(s EventSink) {
	e.mu.Lock()
	e.sink = s
	e.mu.Unlock()
}

// Emit sends an event to the sink directly, without re-evaluating rules. It is
// used to emit a query event AFTER its result set has been fingerprinted (CDFC):
// the block decision was already made and enforced at query time via Decide, and
// this call carries the deferred event together with meta.Tokens.
func (e *Engine) Emit(action Action, ruleName, sql string, meta QueryMeta) {
	e.mu.RLock()
	sink := e.sink
	e.mu.RUnlock()
	if sink != nil && action != ActionIgnore {
		sink(action, ruleName, sql, meta)
	}
}

// Reload atomically replaces the rule set (e.g. after pulling from the console).
func (e *Engine) Reload(rules []*Rule) {
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
}

// Evaluate returns the first matching rule's decision and emits an event to the
// sink (unless the action is Ignore). meta carries per-query connection context
// for correlation. If no rule matches, ActionAllow is returned.
func (e *Engine) Evaluate(sql, username, database string, meta QueryMeta) Decision {
	e.mu.RLock()
	rules := e.rules
	sink := e.sink
	e.mu.RUnlock()

	for _, rule := range rules {
		if rule.matches(sql, username, database) {
			d := Decision{Action: rule.Action, Rule: rule.Name}
			if sink != nil && d.Action != ActionIgnore {
				sink(d.Action, d.Rule, sql, meta)
			}
			return d
		}
	}
	d := Decision{Action: ActionAllow, Rule: "default-allow"}
	if sink != nil {
		sink(d.Action, d.Rule, sql, meta)
	}
	return d
}

// Decide returns the matching rule's decision WITHOUT emitting an event to the
// sink. Use it for block checks at prepare time (PostgreSQL Parse), where the
// correlation-relevant execution event is emitted later via Evaluate on Execute.
func (e *Engine) Decide(sql, username, database string) Decision {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	for _, rule := range rules {
		if rule.matches(sql, username, database) {
			return Decision{Action: rule.Action, Rule: rule.Name}
		}
	}
	return Decision{Action: ActionAllow, Rule: "default-allow"}
}
