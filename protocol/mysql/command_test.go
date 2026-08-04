package mysql

import "testing"

func TestExtractQuery_Classic(t *testing.T) {
	payload := append([]byte{byte(ComQuery)}, "SELECT 1"...)
	sql, ok := ExtractQuery(payload, false)
	if !ok || sql != "SELECT 1" {
		t.Fatalf("ExtractQuery = (%q, %v), want (\"SELECT 1\", true)", sql, ok)
	}
}

func TestExtractQuery_NotAQuery(t *testing.T) {
	if _, ok := ExtractQuery([]byte{byte(ComQuit)}, false); ok {
		t.Error("ExtractQuery on COM_QUIT returned ok=true, want false")
	}
	if _, ok := ExtractQuery(nil, false); ok {
		t.Error("ExtractQuery on empty payload returned ok=true, want false")
	}
}

func TestExtractQuery_QueryAttrsNoParams(t *testing.T) {
	// [0x03][param_count=0][param_set_count=1][query]
	payload := []byte{byte(ComQuery), 0x00, 0x01}
	payload = append(payload, "SELECT 2"...)

	sql, ok := ExtractQuery(payload, true)
	if !ok || sql != "SELECT 2" {
		t.Fatalf("ExtractQuery = (%q, %v), want (\"SELECT 2\", true)", sql, ok)
	}
}

func TestExtractQuery_QueryAttrsWithParams(t *testing.T) {
	// param_count=2: a parameter block follows that we cannot skip yet.
	payload := []byte{byte(ComQuery), 0x02, 0x01, 0xde, 0xad}
	if _, ok := ExtractQuery(payload, true); ok {
		t.Error("ExtractQuery with parameters returned ok=true, want false")
	}
}

func TestExtractQuery_ClassicWhenAttrsByteIsQuery(t *testing.T) {
	// Guard against treating queryAttrs=false specially: a classic COM_QUERY
	// whose text happens to start with bytes < 0xfb must come through intact.
	payload := append([]byte{byte(ComQuery)}, "DROP TABLE t"...)
	sql, ok := ExtractQuery(payload, false)
	if !ok || sql != "DROP TABLE t" {
		t.Fatalf("ExtractQuery = (%q, %v), want (\"DROP TABLE t\", true)", sql, ok)
	}
}

func TestCommandString(t *testing.T) {
	cases := map[Command]string{
		ComQuery:       "COM_QUERY",
		ComQuit:        "COM_QUIT",
		ComStmtPrepare: "COM_STMT_PREPARE",
		Command(0x99):  "COM_UNKNOWN(0x99)",
	}
	for cmd, want := range cases {
		if got := cmd.String(); got != want {
			t.Errorf("Command(0x%02x).String() = %q, want %q", byte(cmd), got, want)
		}
	}
}

func TestReadLenEncInt(t *testing.T) {
	cases := []struct {
		name  string
		in    []byte
		value uint64
		n     int
		ok    bool
	}{
		{"1-byte", []byte{0x0a}, 10, 1, true},
		{"2-byte", []byte{0xfc, 0x01, 0x01}, 257, 3, true},
		{"3-byte", []byte{0xfd, 0x00, 0x01, 0x00}, 256, 4, true},
		{"8-byte", []byte{0xfe, 0x01, 0, 0, 0, 0, 0, 0, 0}, 1, 9, true},
		{"empty", nil, 0, 0, false},
		{"truncated-2-byte", []byte{0xfc, 0x01}, 0, 0, false},
		{"invalid-0xff", []byte{0xff}, 0, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			value, n, ok := readLenEncInt(c.in)
			if value != c.value || n != c.n || ok != c.ok {
				t.Errorf("readLenEncInt(% x) = (%d, %d, %v), want (%d, %d, %v)",
					c.in, value, n, ok, c.value, c.n, c.ok)
			}
		})
	}
}
