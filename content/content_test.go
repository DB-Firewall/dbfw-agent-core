package content

import (
	"strings"
	"testing"
)

func classesOf(tokens []string) map[string]int {
	m := map[string]int{}
	for _, t := range tokens {
		m[strings.SplitN(t, ":", 2)[0]]++
	}
	return m
}

func TestFingerprintExtractsClasses(t *testing.T) {
	h := NewHasher("shared-secret")
	text := `{"id":"550e8400-e29b-41d4-a716-446655440000","email":"Alice@Example.COM",` +
		`"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123DEF456",` +
		`"digest":"d41d8cd98f00b204e9800998ecf8427e"}`
	toks := h.Fingerprint(text, 32)
	got := classesOf(toks)
	for _, want := range []string{"uuid", "email", "jwt", "hexdigest"} {
		if got[want] == 0 {
			t.Errorf("expected a %q token, got classes %v", want, got)
		}
	}
}

func TestFingerprintDeterministicAndKeyed(t *testing.T) {
	a := NewHasher("secret-A")
	b := NewHasher("secret-A")
	c := NewHasher("secret-B")
	text := "user 550e8400-e29b-41d4-a716-446655440000"
	if got, want := a.Fingerprint(text, 8), b.Fingerprint(text, 8); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("same key must be deterministic: %v vs %v", got, want)
	}
	if strings.Join(a.Fingerprint(text, 8), ",") == strings.Join(c.Fingerprint(text, 8), ",") {
		t.Fatalf("different keys must produce different hashes")
	}
}

func TestEmailCanonicalizedLowercase(t *testing.T) {
	h := NewHasher("k")
	upper := h.Fingerprint("X@Example.COM", 8)
	lower := h.Fingerprint("x@example.com", 8)
	if strings.Join(upper, ",") != strings.Join(lower, ",") {
		t.Errorf("email must be case-normalized: %v vs %v", upper, lower)
	}
}

func TestMaxNBound(t *testing.T) {
	h := NewHasher("k")
	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString("550e8400-e29b-41d4-a716-4466554400")
		b.WriteString(string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)))
		b.WriteByte('\n')
	}
	if got := len(h.Fingerprint(b.String(), 10)); got > 10 {
		t.Errorf("maxN not respected: got %d tokens", got)
	}
}

func TestCredentialTextDropped(t *testing.T) {
	h := NewHasher("k")
	if toks := h.Fingerprint("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaa.bbbbbbbbbbbb", 8); toks != nil {
		t.Errorf("credential-looking text must be dropped, got %v", toks)
	}
}

func TestEmptyText(t *testing.T) {
	h := NewHasher("k")
	if toks := h.Fingerprint("", 8); toks != nil {
		t.Errorf("empty text must yield nil, got %v", toks)
	}
}
