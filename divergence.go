package resolver

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"darvaza.org/cache/x/simplelru"
	"darvaza.org/resolver/pkg/exdns"
)

// ResolveMeta provides extra information about a resolve operation.
type ResolveMeta struct {
	Compared     bool
	Diverged     bool
	DivergenceID string
}

// DivergenceObserver records a mismatch between two responses.
type DivergenceObserver func(a, b *dns.Msg, aServer, bServer string) string

// ResponseSnapshot captures a response in a comparable, TTL-free form.
type ResponseSnapshot struct {
	Rcode         int
	Authoritative bool
	Truncated     bool
	Answer        []string
	Authority     []string
}

// Equal reports whether two snapshots are equivalent.
func (s ResponseSnapshot) Equal(o ResponseSnapshot) bool {
	if s.Rcode != o.Rcode || s.Authoritative != o.Authoritative || s.Truncated != o.Truncated {
		return false
	}
	return slices.Equal(s.Answer, o.Answer) && slices.Equal(s.Authority, o.Authority)
}

func snapshotResponse(resp *dns.Msg) ResponseSnapshot {
	if resp == nil {
		return ResponseSnapshot{}
	}

	return ResponseSnapshot{
		Rcode:         resp.Rcode,
		Authoritative: resp.Authoritative,
		Truncated:     resp.Truncated,
		Answer:        canonicalRRs(resp.Answer),
		Authority:     canonicalRRs(resp.Ns),
	}
}

func canonicalRRs(rrs []dns.RR) []string {
	if len(rrs) == 0 {
		return nil
	}

	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		c := dns.Copy(rr)
		c.Header().Ttl = 0
		out = append(out, exdns.CleanString(c))
	}

	sort.Strings(out)
	return out
}

func responsesEqual(a, b *dns.Msg) bool {
	return snapshotResponse(a).Equal(snapshotResponse(b))
}

// DivergenceRecord holds details about a detected response divergence.
type DivergenceRecord struct {
	ID      string
	When    time.Time
	Name    string
	QType   uint16
	AServer string
	BServer string
	A       ResponseSnapshot
	B       ResponseSnapshot
}

type divergenceQuery struct {
	name  string
	qType uint16
}

type divergencePair struct {
	a       *dns.Msg
	b       *dns.Msg
	aServer string
	bServer string
}

func newDivergenceRecord(q divergenceQuery, p divergencePair) *DivergenceRecord {
	return &DivergenceRecord{
		When:    time.Now().UTC(),
		Name:    q.name,
		QType:   q.qType,
		AServer: p.aServer,
		BServer: p.bServer,
		A:       snapshotResponse(p.a),
		B:       snapshotResponse(p.b),
	}
}

// DivergenceStore stores recent divergence records.
type DivergenceStore struct {
	mu  sync.Mutex
	lru *simplelru.LRU[string, []byte]
	ttl time.Duration
	seq atomic.Uint64
}

// NewDivergenceStore creates a bounded divergence store.
func NewDivergenceStore(maxEntries int, ttl time.Duration) *DivergenceStore {
	if maxEntries <= 0 || ttl <= 0 {
		return nil
	}

	cacheBytes := int64(maxEntries) * 1024
	onSet := func(string, []byte, int64, *time.Time) {}
	onEvict := func(string, []byte, int64) {}
	onAdd := func(key string, data []byte, size int, expire time.Time) {
		var ex *time.Time
		if !expire.IsZero() {
			ex = &expire
		}
		onSet(key, data, int64(size), ex)
	}
	onRemove := func(key string, data []byte, size int) {
		onEvict(key, data, int64(size))
	}

	return &DivergenceStore{
		lru: simplelru.NewLRU[string](int(cacheBytes), onAdd, onRemove),
		ttl: ttl,
	}
}

// Add stores a divergence record and returns its ID.
func (ds *DivergenceStore) Add(rec *DivergenceRecord) string {
	if ds == nil || rec == nil {
		return ""
	}

	if rec.ID == "" {
		rec.ID = fmt.Sprintf("%x", ds.seq.Add(1))
	}

	data, ok := marshalDivergenceRecord(rec)
	if !ok {
		return ""
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	expire := time.Now().UTC().Add(ds.ttl)
	ds.lru.Add(rec.ID, data, len(data), expire)
	return rec.ID
}

// Get returns a stored divergence record by ID.
func (ds *DivergenceStore) Get(id string) (*DivergenceRecord, bool) {
	if ds == nil || id == "" {
		return nil, false
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	data, _, ok := ds.lru.Get(id)
	if !ok {
		return nil, false
	}

	rec, ok := unmarshalDivergenceRecord(data)
	return rec, ok
}

func marshalDivergenceRecord(rec *DivergenceRecord) ([]byte, bool) {
	if rec == nil {
		return nil, false
	}

	data, err := json.Marshal(rec)
	return data, err == nil
}

func unmarshalDivergenceRecord(data []byte) (*DivergenceRecord, bool) {
	if len(data) == 0 {
		return nil, false
	}

	var rec DivergenceRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, false
	}
	return &rec, true
}
