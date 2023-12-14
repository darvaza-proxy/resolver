package exdns

import (
	"fmt"

	"darvaza.org/core"
)

// AsServerAddress validates and optionally appends :53 port if
// it wasn't specified already
func AsServerAddress(server string) (string, error) {
	host, port, err := core.SplitHostPort(server)
	if err != nil {
		return "", err
	}

	if port == "" {
		port = "53"
	}

	addr, err := core.ParseAddr(host)
	switch {
	case err != nil:
		return "", err
	case addr.Is6():
		return fmt.Sprintf("[%s]:%s", host, port), nil
	default:
		return host + ":" + port, nil
	}
}

// Decanonize removes the trailing . if present, unless
// it's the root dot
func Decanonize(qName string) string {
	if l := len(qName); l > 1 {
		if qName[l-1] == '.' {
			return qName[:l-1]
		}
	}
	return qName
}
