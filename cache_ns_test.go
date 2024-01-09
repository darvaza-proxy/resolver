package resolver

import "testing"

type SuffixCases struct {
	Name     string
	Suffixes []string
}

func (tc *SuffixCases) Test(t *testing.T, nsc *NSCache) {
	var fail bool

	s := nsc.Suffixes(tc.Name)
	switch {
	case len(s) != len(tc.Suffixes):
		fail = true
	default:
		for i := range s {
			if s[i] != tc.Suffixes[i] {
				fail = true
				break
			}
		}
	}

	if fail {
		t.Errorf("%s%q -> %q", "ERROR: ", tc.Name, s)
	} else {
		t.Logf("%s%q -> %q", "", tc.Name, s)
	}
}

func TS(s ...string) SuffixCases {
	return SuffixCases{
		Name:     s[0],
		Suffixes: s,
	}
}

func TestNSCacheSuffixes(t *testing.T) {
	var nsc *NSCache

	var cases = []SuffixCases{
		TS("www.miek.nl.", "miek.nl.", "nl.", "."),
	}

	for _, tc := range cases {
		tc.Test(t, nsc)
	}
}
