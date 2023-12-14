// Package exdns contains helpers to work with [dns.Msg]
package exdns

import "github.com/miekg/dns"

// ForEachAnswer calls a function for each answer of the specified type.
func ForEachAnswer[T dns.RR](msg *dns.Msg, fn func(v T)) {
	if fn == nil || msg == nil {
		return
	}

	for _, ans := range msg.Answer {
		if v, ok := ans.(T); ok {
			fn(v)
		}
	}
}

// GetFirstAnswer returns the first answer for a specified type
func GetFirstAnswer[T dns.RR](msg *dns.Msg) T {
	var zero T

	if msg != nil {
		for _, ans := range msg.Answer {
			if v, ok := ans.(T); ok {
				return v
			}
		}
	}

	return zero
}

// HasAnswerType checks if a [dns.Msg] contains answers of the
// specified type.
func HasAnswerType(msg *dns.Msg, qType uint16) bool {
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == qType {
			return true
		}
	}
	return false
}

// HasNsType checks if a [dns.Msg] contains Ns entries of the
// specified type
func HasNsType(msg *dns.Msg, qType uint16) bool {
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == qType {
			return true
		}
	}
	return false
}

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
