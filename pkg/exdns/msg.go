// Package exdns contains helpers to work with [dns.Msg]
package exdns

import "github.com/miekg/dns"

// ForEachAnswer calls a function for each answer of the specified type.
func ForEachAnswer[T dns.RR](msg *dns.Msg, fn func(v T)) {
	if msg != nil {
		ForEachRR[T](msg.Answer, fn)
	}
}

// ForEachRR calls a function for each [dns.RR] of the specified type.
func ForEachRR[T dns.RR](records []dns.RR, fn func(v T)) {
	if fn == nil || len(records) == 0 {
		return
	}

	for _, rr := range records {
		if v, ok := rr.(T); ok {
			fn(v)
		}
	}
}

// ForEachQuestion calls a function for each question on the given request.
func ForEachQuestion(req *dns.Msg, fn func(dns.Question)) {
	if req == nil || fn == nil {
		return
	}

	for _, q := range req.Question {
		fn(q)
	}
}

// ForEachQuestionOfClass calls a function for each question of the specified class
// on the given request
func ForEachQuestionOfClass(req *dns.Msg, qClass uint16, fn func(dns.Question)) {
	if req == nil || fn == nil {
		return
	}

	ForEachQuestion(req, func(q dns.Question) {
		if q.Qclass == qClass {
			fn(q)
		}
	})
}

// GetFirstAnswer returns the first answer for a specified type.
func GetFirstAnswer[T dns.RR](msg *dns.Msg) T {
	var zero T

	if msg != nil {
		v, ok := GetFirstRR[T](msg.Answer)
		if ok {
			return v
		}
	}

	return zero
}

// GetFirstRR returns the first RR for a specified type on the
// given slice.
func GetFirstRR[T dns.RR](records []dns.RR) (T, bool) {
	var zero T

	for _, rr := range records {
		if v, ok := rr.(T); ok {
			return v, true
		}
	}

	return zero, false
}

// HasAnswerType checks if a [dns.Msg] contains answers of the
// specified type.
func HasAnswerType(msg *dns.Msg, qType uint16) bool {
	if msg != nil {
		for _, rr := range msg.Answer {
			if rr.Header().Rrtype == qType {
				return true
			}
		}
	}
	return false
}

// HasNsType checks if a [dns.Msg] contains Ns entries of the
// specified type
func HasNsType(msg *dns.Msg, qType uint16) bool {
	if msg != nil {
		for _, rr := range msg.Ns {
			if rr.Header().Rrtype == qType {
				return true
			}
		}
	}
	return false
}

// NewRequestFromParts creates a new [dns.Msg] from the described question.
func NewRequestFromParts(qName string, qClass uint16, qType uint16) *dns.Msg {
	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: false,
		},
		Question: []dns.Question{
			{
				Name:   qName,
				Qclass: qClass,
				Qtype:  qType,
			},
		},
	}

	req = req.SetEdns0(dns.DefaultMsgSize, false)
	return req
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
