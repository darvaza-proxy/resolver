// Package exdns contains helpers to work with [dns.Msg]
package exdns

import "github.com/miekg/dns"

// TrimQ removes entries matching the condition from a dns.Question slice
func TrimQ(s []dns.Question, cond func(q dns.Question) bool) []dns.Question {
	var j int

	for i, q := range s {
		if !cond(q) {
			if i != j {
				s[j] = q
			}
			j++
		}
	}

	return s[:j]
}

// TrimRR removes entries matching the condition from a dns.RR slice
func TrimRR(s []dns.RR, cond func(rr dns.RR) bool) []dns.RR {
	var j int

	for i, rr := range s {
		if !cond(rr) {
			if i != j {
				s[j] = rr
			}
			j++
		}
	}

	return s[:j]
}
