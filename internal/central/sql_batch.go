package central

import (
	"fmt"
	"strings"
)

// appendSQLTuple appends values to args and returns a PostgreSQL placeholder
// tuple for them, e.g. ($1,$2,$3). It keeps the batch-building code in the
// telemetry hot path readable while still using bind parameters for every
// value.
func appendSQLTuple(args *[]interface{}, values ...interface{}) string {
	placeholders := make([]string, len(values))
	for i, value := range values {
		*args = append(*args, value)
		placeholders[i] = fmt.Sprintf("$%d", len(*args))
	}
	return "(" + strings.Join(placeholders, ",") + ")"
}

// appendSQLTypedTuple is the typed counterpart used for PostgreSQL VALUES
// batches whose parameters otherwise have no target-column context during
// parse/type inference. Casting each placeholder inside VALUES prevents pgx/
// PostgreSQL from resolving an entire parameter column as text before the
// outer SELECT is evaluated.
func appendSQLTypedTuple(args *[]interface{}, casts []string, values ...interface{}) string {
	if len(casts) != len(values) {
		panic("appendSQLTypedTuple: casts/value length mismatch")
	}
	placeholders := make([]string, len(values))
	for i, value := range values {
		*args = append(*args, value)
		placeholders[i] = fmt.Sprintf("$%d::%s", len(*args), casts[i])
	}
	return "(" + strings.Join(placeholders, ",") + ")"
}
