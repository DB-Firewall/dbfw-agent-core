package mysql

import "testing"

func TestCapabilitiesHas(t *testing.T) {
	caps := ClientProtocol41 | ClientSSL
	if !caps.Has(ClientSSL) {
		t.Error("Has(ClientSSL) = false, want true")
	}
	if caps.Has(ClientQueryAttributes) {
		t.Error("Has(ClientQueryAttributes) = true, want false")
	}
}

func TestClientCapabilitiesFromHandshakeResponse(t *testing.T) {
	// ClientSSL (1<<11) | ClientProtocol41 (1<<9) = 0x00000a00, little-endian.
	payload := []byte{0x00, 0x0a, 0x00, 0x00, 0xff, 0xff}
	caps, ok := ClientCapabilitiesFromHandshakeResponse(payload)
	if !ok {
		t.Fatal("ok = false, want true for a 4+ byte payload")
	}
	if !caps.Has(ClientSSL) || !caps.Has(ClientProtocol41) {
		t.Errorf("caps = 0x%08x, want ClientSSL and ClientProtocol41 set", uint32(caps))
	}
}

func TestClientCapabilitiesFromHandshakeResponse_TooShort(t *testing.T) {
	if _, ok := ClientCapabilitiesFromHandshakeResponse([]byte{0x00, 0x0a}); ok {
		t.Error("ok = true for a 2-byte payload, want false")
	}
}
