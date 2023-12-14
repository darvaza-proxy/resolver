package exdns

import "testing"

func TestDecanonize(t *testing.T) {
	tests := []struct {
		name   string
		result string
	}{
		{"", ""},
		{".", "."},
		{"google.com.", "google.com"},
		{"google.com", "google.com"},
		{"com", "com"},
		{"com.", "com"},
	}

	for _, tc := range tests {
		result := Decanonize(tc.name)
		if result == tc.result {
			t.Logf("%q became %q", tc.name, result)
		} else {
			t.Errorf("%q became %q, expected %q", tc.name, result, tc.result)
		}
	}
}
