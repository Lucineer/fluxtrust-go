package fluxtrust

import "sort"

type TrustConfig struct {
	PositiveWeight, NegativeWeight, MaxTrust float64
	DecayPerHour, NoneThreshold, TrustedThreshold float64
}

type TrustEntry struct {
	AgentID      uint16
	Score        float64
	Positive     uint32
	Negative     uint32
	Observations uint32
	Revoked      bool
	Created      int64
	LastSeen     int64
	MaxTrust     float64
}

type TrustTable struct {
	entries map[uint16]*TrustEntry
}

func NewTrustTable() *TrustTable {
	return &TrustTable{entries: make(map[uint16]*TrustEntry)}
}

func (t *TrustTable) getOrCreate(id uint16, now int64) *TrustEntry {
	if e, ok := t.entries[id]; ok {
		return e
	}
	e := &TrustEntry{AgentID: id, Created: now, LastSeen: now}
	t.entries[id] = e
	return e
}

func (t *TrustTable) Score(id uint16) float64 {
	if e, ok := t.entries[id]; ok {
		if e.Revoked {
			return -1
		}
		return e.Score
	}
	return -1
}

func (t *TrustTable) Observe(id uint16, positive bool, cfg *TrustConfig, now int64) {
	if e, ok := t.entries[id]; ok && e.Revoked {
		return
	}
	e := t.getOrCreate(id, now)
	e.LastSeen = now
	if positive {
		e.Positive++
	} else {
		e.Negative++
	}
	e.Observations++

	// Bayesian update: score based on weighted success rate
	total := float64(e.Positive)*cfg.PositiveWeight + float64(e.Negative)*cfg.NegativeWeight
	if total == 0 {
		e.Score = 0
	} else {
		e.Score = (float64(e.Positive) * cfg.PositiveWeight) / total
	}

	// Clamp and track max
	if e.Score > cfg.MaxTrust {
		e.Score = cfg.MaxTrust
	}
	if e.Score > e.MaxTrust {
		e.MaxTrust = e.Score
	}
}

func (t *TrustTable) Revoke(id uint16) {
	if e, ok := t.entries[id]; ok {
		e.Revoked = true
	}
}

func (t *TrustTable) Decay(cfg *TrustConfig, hours float64) {
	for _, e := range t.entries {
		if e.Revoked {
			continue
		}
		e.Score *= 1 - cfg.DecayPerHour*hours
		if e.Score < 0 {
			e.Score = 0
		}
	}
}

func (t *TrustTable) IsTrusted(id uint16, cfg *TrustConfig) bool {
	if e, ok := t.entries[id]; ok && !e.Revoked {
		return e.Score >= cfg.TrustedThreshold
	}
	return false
}

func (t *TrustTable) Count() int {
	return len(t.entries)
}

func (t *TrustTable) MostTrusted(n int) []*TrustEntry {
	all := t.sortedEntries(func(a, b *TrustEntry) bool { return a.Score > b.Score })
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

func (t *TrustTable) LeastTrusted(n int) []*TrustEntry {
	all := t.sortedEntries(func(a, b *TrustEntry) bool { return a.Score < b.Score })
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

func (t *TrustTable) CountTrusted(cfg *TrustConfig) int {
	count := 0
	for _, e := range t.entries {
		if !e.Revoked && e.Score >= cfg.TrustedThreshold {
			count++
		}
	}
	return count
}

func (t *TrustTable) sortedEntries(less func(a, b *TrustEntry) bool) []*TrustEntry {
	all := make([]*TrustEntry, 0, len(t.entries))
	for _, e := range t.entries {
		all = append(all, e)
	}
	sort.Slice(all, func(i, j int) bool { return less(all[i], all[j]) })
	return all
}
