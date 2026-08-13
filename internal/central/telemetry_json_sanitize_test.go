package central

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

func TestSanitizeJSONNULReplacesActualNUL(t *testing.T) {
	raw := json.RawMessage(`{"file_name":"bad\u0000name","nested":["ok","x\u0000y"],"n":9007199254740993}`)
	clean, count, err := sanitizeJSONNUL(raw)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("replacements=%d want 2", count)
	}
	if strings.Contains(string(clean), `\u0000`) {
		t.Fatalf("sanitized JSON still contains NUL escape: %s", clean)
	}
	if !strings.Contains(string(clean), `9007199254740993`) {
		t.Fatalf("large integer precision changed: %s", clean)
	}
	var decoded map[string]any
	dec := json.NewDecoder(strings.NewReader(string(clean)))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if got := decoded["file_name"]; got != "bad\uFFFDname" {
		t.Fatalf("file_name=%q", got)
	}
}

func TestSanitizeJSONNULLiteralEscapeIsUntouched(t *testing.T) {
	// JSON string value is the six literal characters "\\u0000", not U+0000.
	raw := json.RawMessage(`{"value":"literal \\u0000 text"}`)
	clean, count, err := sanitizeJSONNUL(raw)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("replacements=%d want 0", count)
	}
	if string(clean) != string(raw) {
		t.Fatalf("literal escape changed: got %s want %s", clean, raw)
	}
}

func TestSanitizeTelemetryJSONForPostgresCoversAllRawFields(t *testing.T) {
	x := management.TelemetrySnapshot{
		Topology:             json.RawMessage(`{"Nodes":[{"Hostname":"a\u0000b"}]}`),
		SMBObservations:      json.RawMessage(`[{"FileName":"x\u0000y"}]`),
		ProtocolObservations: json.RawMessage(`[{"resource":"r\u0000s"}]`),
		UDPTelemetry:         json.RawMessage(`{"ok":true}`),
	}
	count, err := sanitizeTelemetryJSONForPostgres(&x)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("replacements=%d want 3", count)
	}
	for name, raw := range map[string]json.RawMessage{
		"topology": x.Topology, "smb": x.SMBObservations, "protocol": x.ProtocolObservations,
	} {
		if strings.Contains(string(raw), `\u0000`) {
			t.Fatalf("%s still contains nul: %s", name, raw)
		}
	}
}
