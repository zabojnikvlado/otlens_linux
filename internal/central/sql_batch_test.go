package central

import (
	"strings"
	"testing"
	"time"
)

func TestAppendSQLTypedTupleCastsValuesParameters(t *testing.T) {
	args := []interface{}{}
	tuple := appendSQLTypedTuple(&args, []string{"text", "timestamptz", "integer", "boolean"}, "sensor-001", time.Unix(1, 0).UTC(), 445, true)
	want := "($1::text,$2::timestamptz,$3::integer,$4::boolean)"
	if tuple != want {
		t.Fatalf("tuple=%q want=%q", tuple, want)
	}
	if len(args) != 4 {
		t.Fatalf("args=%d want=4", len(args))
	}
	if strings.Contains(tuple, "$2,") {
		t.Fatal("timestamp placeholder lost explicit cast")
	}
}
