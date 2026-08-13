package central

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

// sanitizeTelemetryJSONForPostgres removes code points that PostgreSQL cannot
// represent inside jsonb. PostgreSQL text/jsonb deliberately rejects U+0000;
// packet-derived strings (for example SMB file names or generic protocol
// resources) can legitimately contain a NUL byte and encoding/json serializes
// it as \u0000. Keep checksum verification on the original wire payload and
// sanitize only the database copy after the payload has been authenticated.
//
// The common path is allocation-free: JSON is decoded/re-encoded only when a
// possible NUL escape/raw NUL is present. Decoding with UseNumber preserves
// integer precision while letting us distinguish a real U+0000 from a literal
// six-character "\\u0000" string.
func sanitizeTelemetryJSONForPostgres(x *management.TelemetrySnapshot) (int, error) {
	if x == nil {
		return 0, nil
	}

	fields := []struct {
		name string
		raw  *json.RawMessage
	}{
		{"topology", &x.Topology},
		{"tags", &x.Tags},
		{"tag_changes", &x.TagChanges},
		{"tag_events", &x.TagEvents},
		{"alerts", &x.Alerts},
		{"baseline", &x.Baseline},
		{"rules", &x.Rules},
		{"dns_observations", &x.DNSObservations},
		{"smb_observations", &x.SMBObservations},
		{"protocol_observations", &x.ProtocolObservations},
		{"udp_conversations", &x.UDPConversations},
		{"udp_telemetry", &x.UDPTelemetry},
		{"udp_protocol_exchanges", &x.UDPProtocolExchanges},
	}

	changed := 0
	for _, field := range fields {
		clean, replacements, err := sanitizeJSONNUL(*field.raw)
		if err != nil {
			return changed, fmt.Errorf("sanitize %s: %w", field.name, err)
		}
		if replacements > 0 {
			*field.raw = clean
			changed += replacements
		}
	}
	return changed, nil
}

func sanitizeJSONNUL(raw json.RawMessage) (json.RawMessage, int, error) {
	if len(raw) == 0 {
		return raw, 0, nil
	}
	// encoding/json emits an actual NUL as \u0000. Also check a raw NUL so
	// malformed/non-standard producers fail closed through the decoder below
	// instead of being passed to PostgreSQL unchanged.
	if !bytes.Contains(raw, []byte(`\u0000`)) && !bytes.Contains(raw, []byte{0}) {
		return raw, 0, nil
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, 0, err
	}
	// Refuse trailing non-whitespace rather than silently changing malformed
	// telemetry into a different JSON value.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, 0, fmt.Errorf("multiple JSON values")
		}
		return nil, 0, err
	}

	clean, replacements := sanitizeJSONValue(value)
	if replacements == 0 {
		// The byte prefilter can match a literal "\\u0000". In that case the
		// decoded string contains no NUL and the original payload is already
		// PostgreSQL-safe, so preserve it byte-for-byte.
		return raw, 0, nil
	}
	encoded, err := json.Marshal(clean)
	if err != nil {
		return nil, 0, err
	}
	return json.RawMessage(encoded), replacements, nil
}

func sanitizeJSONValue(value any) (any, int) {
	switch v := value.(type) {
	case string:
		count := strings.Count(v, "\x00")
		if count == 0 {
			return v, 0
		}
		return strings.ReplaceAll(v, "\x00", "\uFFFD"), count
	case []any:
		total := 0
		for i := range v {
			clean, n := sanitizeJSONValue(v[i])
			v[i] = clean
			total += n
		}
		return v, total
	case map[string]any:
		total := 0
		out := make(map[string]any, len(v))
		for key, item := range v {
			cleanKey := key
			if n := strings.Count(cleanKey, "\x00"); n > 0 {
				cleanKey = strings.ReplaceAll(cleanKey, "\x00", "\uFFFD")
				total += n
			}
			clean, n := sanitizeJSONValue(item)
			out[cleanKey] = clean
			total += n
		}
		return out, total
	default:
		return value, 0
	}
}
