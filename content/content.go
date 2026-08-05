// Package content extracts high-entropy "opaque leaf" tokens from text — DB
// result-set values or HTTP response bodies — and fingerprints them with a keyed
// hash, for Content / Data-Flow Correlation (CDFC).
//
// Only rare, transformation-surviving values are kept (UUIDs, emails, JWTs, long
// hex/base64url blobs, hex digests). Structure (JSON shape, field names) and
// low-entropy values (dates, small ints, words) are deliberately ignored, because
// application transforms rewrite containers but pass high-entropy identifiers
// through byte-for-byte.
//
// Raw values never leave the capture point: only class-tagged, keyed-hash tokens
// ("class:hex") are emitted. The key is derived from the shared console secret so
// the DB agent and the gateway produce identical hashes without transmitting it.
package content

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

type classPattern struct {
	class string
	re    *regexp.Regexp
	lower bool // canonicalize match to lowercase (must match the gateway side)
}

// patterns are the opaque-leaf token classes, most specific first. The same
// grammar MUST run byte-for-byte on the HTTP (gateway) side — see the Lua port.
var patterns = []classPattern{
	{"uuid", regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`), true},
	{"email", regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`), true},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`), false},
	{"hexdigest", regexp.MustCompile(`\b[0-9a-fA-F]{32,64}\b`), true},
	{"opaque", regexp.MustCompile(`[A-Za-z0-9_\-]{20,}`), false},
}

// credBlock matches text that looks like a live credential; such values are never
// fingerprinted so secrets are not hashed into the store.
var credBlock = regexp.MustCompile(`(?i)(bearer |authorization|password|secret|apikey|api_key|set-cookie)`)

// Hasher fingerprints text using an HMAC key derived from the console secret.
type Hasher struct {
	key []byte
}

// NewHasher derives the HMAC key from the shared secret. Both the DB agent and
// the gateway call this with the same secret, yielding matching hashes without
// ever transmitting the key.
func NewHasher(secret string) *Hasher {
	sum := sha256.Sum256([]byte("dbfw-cdfc|" + secret))
	return &Hasher{key: sum[:]}
}

// Fingerprint scans text, extracts distinct high-entropy tokens, and returns up
// to maxN of them as "class:hex24" strings (96-bit truncated HMAC-SHA256),
// longest-first (length as an entropy proxy). Returns nil for empty text or text
// that looks like a credential.
func (h *Hasher) Fingerprint(text string, maxN int) []string {
	if text == "" || credBlock.MatchString(text) {
		return nil
	}
	type tok struct {
		s string
		n int
	}
	seen := make(map[string]bool)
	var toks []tok
	for _, p := range patterns {
		for _, m := range p.re.FindAllString(text, -1) {
			canon := m
			if p.lower {
				canon = strings.ToLower(canon)
			}
			dedup := p.class + "\x00" + canon
			if seen[dedup] {
				continue
			}
			seen[dedup] = true
			toks = append(toks, tok{h.token(p.class, canon), len(canon)})
		}
	}
	sort.SliceStable(toks, func(i, j int) bool { return toks[i].n > toks[j].n })
	if maxN > 0 && len(toks) > maxN {
		toks = toks[:maxN]
	}
	out := make([]string, len(toks))
	for i, t := range toks {
		out[i] = t.s
	}
	return out
}

// FingerprintValues fingerprints a set of already-isolated values (e.g. DB column
// values), concatenating their per-value tokens up to maxN.
func (h *Hasher) FingerprintValues(values []string, maxN int) []string {
	if len(values) == 0 {
		return nil
	}
	return h.Fingerprint(strings.Join(values, "\n"), maxN)
}

func (h *Hasher) token(class, canon string) string {
	mac := hmac.New(sha256.New, h.key)
	mac.Write([]byte(class + ":" + canon))
	sum := mac.Sum(nil)
	return class + ":" + hex.EncodeToString(sum[:12]) // 96-bit
}
