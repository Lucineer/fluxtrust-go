package fluxtrust

import "testing"

func newTestConfig() *TrustConfig {
	return &TrustConfig{
		PositiveWeight:  1.0,
		NegativeWeight:  2.0,
		MaxTrust:       1.0,
		DecayPerHour:    0.01,
		NoneThreshold:   0.1,
		TrustedThreshold: 0.5,
	}
}

func TestNewTrustTable(t *testing.T) {
	tt := NewTrustTable()
	if tt == nil {
		t.Fatal("nil table")
	}
	if tt.Count() != 0 {
		t.Fatalf("expected 0, got %d", tt.Count())
	}
}

func TestScoreUnknown(t *testing.T) {
	tt := NewTrustTable()
	if s := tt.Score(1); s != -1 {
		t.Fatalf("expected -1 for unknown, got %f", s)
	}
}

func TestScoreRevoked(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	tt.Observe(1, true, cfg, 100)
	tt.Revoke(1)
	if s := tt.Score(1); s != -1 {
		t.Fatalf("expected -1 for revoked, got %f", s)
	}
}

func TestObservePositive(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	tt.Observe(1, true, cfg, 100)
	if tt.Count() != 1 {
		t.Fatalf("expected 1 entry, got %d", tt.Count())
	}
	e := tt.entries[1]
	if e.Positive != 1 || e.Observations != 1 || e.LastSeen != 100 {
		t.Fatalf("unexpected entry state: %+v", e)
	}
}

func TestObserveNegative(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	tt.Observe(1, false, cfg, 100)
	e := tt.entries[1]
	if e.Negative != 1 || e.Observations != 1 {
		t.Fatalf("unexpected: %+v", e)
	}
}

func TestBayesianScore(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	// 1 positive (weight 1), 0 negative → score = 1/(1+0) = 1.0
	tt.Observe(1, true, cfg, 100)
	if s := tt.Score(1); s != 1.0 {
		t.Fatalf("expected 1.0, got %f", s)
	}
}

func TestBayesianScoreMixed(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	// 1 pos (w=1), 1 neg (w=2) → score = 1/(1+2) = 0.333
	tt.Observe(1, true, cfg, 100)
	tt.Observe(1, false, cfg, 101)
	if s := tt.Score(1); s < 0.33 || s > 0.34 {
		t.Fatalf("expected ~0.333, got %f", s)
	}
}

func TestBayesianScoreAllNegative(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	tt.Observe(1, false, cfg, 100)
	if s := tt.Score(1); s != 0.0 {
		t.Fatalf("expected 0.0, got %f", s)
	}
}

func TestRevoke(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	tt.Observe(1, true, cfg, 100)
	tt.Revoke(1)
	if !tt.entries[1].Revoked {
		t.Fatal("expected revoked")
	}
}

func TestRevokeNonexistent(t *testing.T) {
	tt := NewTrustTable()
	// should not panic
	tt.Revoke(99)
}

func TestDecay(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	tt.Observe(1, true, cfg, 100) // score = 1.0
	tt.Decay(cfg, 10)            // 1.0 * (1 - 0.01*10) = 0.9
	if s := tt.Score(1); s < 0.89 || s > 0.91 {
		t.Fatalf("expected ~0.9, got %f", s)
	}
}

func TestDecayDoesNotGoBelowZero(t *testing.T) {
	tt := NewTrustTable()
	cfg := &TrustConfig{PositiveWeight: 1, NegativeWeight: 1, MaxTrust: 1, DecayPerHour: 1.0, NoneThreshold: 0.1, TrustedThreshold: 0.5}
	tt.Observe(1, true, cfg, 100)
	tt.Decay(cfg, 1000) // massive decay
	if s := tt.Score(1); s < 0 {
		t.Fatalf("expected >= 0, got %f", s)
	}
}

func TestDecaySkipsRevoked(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	tt.Observe(1, true, cfg, 100)
	tt.Observe(2, true, cfg, 100)
	tt.Revoke(1)
	tt.Decay(cfg, 10)
	// entry 1 should remain at score 1.0 (skipped), 2 should be 0.9
	if s := tt.entries[1].Score; s != 1.0 {
		t.Fatalf("revoked score should be untouched, got %f", s)
	}
	if s := tt.entries[2].Score; s < 0.89 || s > 0.91 {
		t.Fatalf("expected ~0.9, got %f", s)
	}
}

func TestIsTrusted(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	tt.Observe(1, true, cfg, 100) // score = 1.0 >= 0.5
	if !tt.IsTrusted(1, cfg) {
		t.Fatal("should be trusted")
	}
}

func TestIsTrustedBelowThreshold(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	tt.Observe(1, true, cfg, 100)
	tt.Observe(1, false, cfg, 101) // score ~0.33 < 0.5
	if tt.IsTrusted(1, cfg) {
		t.Fatal("should not be trusted")
	}
}

func TestIsTrustedUnknown(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	if tt.IsTrusted(99, cfg) {
		t.Fatal("unknown should not be trusted")
	}
}

func TestCount(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	if tt.Count() != 0 {
		t.Fatalf("expected 0, got %d", tt.Count())
	}
	tt.Observe(1, true, cfg, 100)
	tt.Observe(2, false, cfg, 100)
	if tt.Count() != 2 {
		t.Fatalf("expected 2, got %d", tt.Count())
	}
}

func TestMostTrusted(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	tt.Observe(1, true, cfg, 100)  // 1.0
	tt.Observe(2, false, cfg, 100) // 0.0
	tt.Observe(3, true, cfg, 100)
	tt.Observe(3, false, cfg, 101) // ~0.33
	top := tt.MostTrusted(2)
	if len(top) != 2 {
		t.Fatalf("expected 2, got %d", len(top))
	}
	if top[0].AgentID != 1 || top[1].AgentID != 3 {
		t.Fatalf("expected [1,3], got [%d,%d]", top[0].AgentID, top[1].AgentID)
	}
}

func TestLeastTrusted(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	tt.Observe(1, true, cfg, 100)  // 1.0
	tt.Observe(2, false, cfg, 100) // 0.0
	tt.Observe(3, true, cfg, 100)
	tt.Observe(3, false, cfg, 101) // ~0.33
	bot := tt.LeastTrusted(2)
	if len(bot) != 2 {
		t.Fatalf("expected 2, got %d", len(bot))
	}
	if bot[0].AgentID != 2 || bot[1].AgentID != 3 {
		t.Fatalf("expected [2,3], got [%d,%d]", bot[0].AgentID, bot[1].AgentID)
	}
}

func TestCountTrusted(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	tt.Observe(1, true, cfg, 100)   // 1.0 → trusted
	tt.Observe(2, false, cfg, 100)  // 0.0 → not
	tt.Observe(3, true, cfg, 100)
	tt.Observe(3, false, cfg, 101)  // ~0.33 → not
	tt.Observe(4, true, cfg, 100)
	tt.Revoke(4)                      // revoked → not counted
	if c := tt.CountTrusted(cfg); c != 1 {
		t.Fatalf("expected 1, got %d", c)
	}
}

func TestMaxTrust(t *testing.T) {
	tt := NewTrustTable()
	cfg := newTestConfig()
	tt.Observe(1, true, cfg, 100) // score=1.0, max=1.0
	tt.Observe(1, false, cfg, 101) // score drops
	if tt.entries[1].MaxTrust != 1.0 {
		t.Fatalf("max trust should be 1.0, got %f", tt.entries[1].MaxTrust)
	}
}

func TestMaxTrustClamp(t *testing.T) {
	cfg := &TrustConfig{PositiveWeight: 1, NegativeWeight: 0, MaxTrust: 0.8, DecayPerHour: 0, NoneThreshold: 0.1, TrustedThreshold: 0.5}
	tt := NewTrustTable()
	tt.Observe(1, true, cfg, 100)
	if s := tt.Score(1); s != 0.8 {
		t.Fatalf("expected 0.8 (clamped), got %f", s)
	}
}
