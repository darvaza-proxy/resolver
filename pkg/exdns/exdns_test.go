package exdns

import "testing"

func TestAsServerAddress(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		ok       bool
	}{
		{"8.8.8.8:53", "8.8.8.8:53", true},
		{"8.8.8.8", "8.8.8.8:53", true},
		{"8.8.8.8.9", "", false},
		{"[2001:4860:4860::8888]:53", "[2001:4860:4860::8888]:53", true},
		{"2001:4860:4860::8888:53", "[2001:4860:4860::8888:53]:53", true},
		{"2001:4860:4860:0000:0000:0000:0000:8888:53", "", false},
		{"2001:4860:4860:0000:0000:0000:0000:8888", "[2001:4860:4860::8888]:53", true},
		{"[2001:4860:4860:0000:0000:0000:0000:8888]:53", "[2001:4860:4860::8888]:53", true},
	}

	for _, tc := range tests {
		if tc.ok && tc.expected == "" {
			// expected the same as the input
			tc.expected = tc.input
		}

		doTestAsServerAddress(t, tc.input, tc.expected, tc.ok)
	}
}

func doTestAsServerAddress(t *testing.T, input, expected string, ok bool) {
	output, err := AsServerAddress(input)

	switch {
	case ok && err != nil:
		t.Errorf("%q conversion failed unexpectedly: %v", input, err)
	case !ok && err == nil:
		t.Errorf("%q conversion failed to fail", input)
	case ok && expected != output:
		t.Errorf("%q conversion resulted in %q instead of %q", input, output, expected)
	default:
		t.Logf("%q conversion resulted in %q", input, output)
	}
}

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
