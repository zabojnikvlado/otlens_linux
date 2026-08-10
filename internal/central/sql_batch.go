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
