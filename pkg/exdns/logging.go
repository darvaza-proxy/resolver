package exdns

import (
	"fmt"
	"strings"
)

// CleanString replaces all whitespace on the `.String()`
// output of a command with single spaces, to turn them into
// readable fields in logs.
func CleanString(v fmt.Stringer) string {
	return strings.Join(strings.Fields(v.String()), " ")
}
