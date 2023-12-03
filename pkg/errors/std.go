package errors

import "errors"

// New creates a simple error wrapping a string
func New(s string) error {
	return errors.New(s)
}
