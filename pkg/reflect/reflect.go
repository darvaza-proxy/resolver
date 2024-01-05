// Package reflect provides a logging layer for exchangers and client
package reflect

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/core"
	"darvaza.org/slog"
)

type reflectOptions struct {
	Name     string
	ID       string
	Request  *dns.Msg
	Response *dns.Msg
	Server   string
	RTT      time.Duration
	Err      error
	Extra    map[string]any
	Rename   map[string]string
}

func doLog(l slog.Logger, level slog.LogLevel, opt reflectOptions) {
	log := l.WithLevel(level)
	if log.Enabled() {
		msg, fields := opt.getFields()

		log.WithFields(fields).Print(msg)
	}
}

func (opt reflectOptions) setField(m slog.Fields, label string, value any) {
	if opt.Rename != nil {
		n, ok := opt.Rename[label]
		switch {
		case !ok:
			// continue
		case n == "":
			// skip
			return
		default:
			// rename
			label = n
		}
	}

	m[label] = value
}

func (opt reflectOptions) setNonZeroField(m slog.Fields, label string, value any) {
	if !core.IsZero(value) {
		opt.setField(m, label, value)
	}
}

func (opt reflectOptions) getFields() (string, slog.Fields) {
	var s string
	var msg *dns.Msg

	switch {
	case opt.Request != nil:
		msg = opt.Request
		s = "request"
	case opt.Response != nil:
		msg = opt.Response
		s = "response"
	default:
		s = "void"
	}

	m := make(map[string]any)
	for k, v := range opt.Extra {
		m[k] = v
	}

	opt.addMsgFields(m, msg)
	opt.addLayerFields(m)

	return s, m
}

func (opt reflectOptions) addMsgFields(m slog.Fields, msg *dns.Msg) {
	if msg != nil {
		opt.setField(m, "compress", msg.Compress)

		opt.addMsgHdrFields(m, &msg.MsgHdr)
		opt.addQuestions(m, msg.Question)
		opt.addAnswers(m, "answer", msg.Answer)
		opt.addAnswers(m, "ns", msg.Ns)
		opt.addAnswers(m, "extra", msg.Extra)
	}
}

func (opt reflectOptions) addMsgHdrFields(m slog.Fields, hdr *dns.MsgHdr) {
	// TODO: in parts
	opt.setField(m, "header", cleanString(hdr))
}

func (opt reflectOptions) addQuestions(m slog.Fields, questions []dns.Question) {
	if len(questions) > 0 {
		var s []string
		for _, q := range questions {
			s = append(s, cleanString(&q))
		}

		opt.setField(m, "question", s)
	}
}

func (opt reflectOptions) addAnswers(m slog.Fields, name string, answers []dns.RR) {
	if len(answers) > 0 {
		var s []string
		for _, rr := range answers {
			s = append(s, cleanString(rr))
		}
		opt.setField(m, name, s)
	}
}

func (opt reflectOptions) addLayerFields(m slog.Fields) {
	opt.setNonZeroField(m, "name", opt.Name)
	opt.setNonZeroField(m, "tracing", opt.ID)
	opt.setNonZeroField(m, "server", opt.Server)
	opt.setNonZeroField(m, slog.ErrorFieldName, opt.Err)

	if d := opt.RTT; d > 0 {
		opt.setField(m, "rtt", d/time.Millisecond)
	}
}

func cleanString(v fmt.Stringer) string {
	return strings.Join(strings.Fields(v.String()), " ")
}
