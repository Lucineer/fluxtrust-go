# fluxtrust-go 🛡️

**Go Bayesian trust scoring for agent fleets.** Track trust scores across agents with positive/negative observations, configurable decay, and hard revocation. Kubernetes-native, microservice-ready.

```go
cfg := fluxtrust.DefaultConfig() // or build custom
tt := fluxtrust.NewTrustTable()

tt.Observe(1, true, cfg, now)   // positive observation
tt.Observe(2, false, cfg, now)  // negative
fmt.Println(tt.Score(1))        // 0.55
fmt.Println(tt.IsTrusted(1, cfg)) // true if >= trusted_threshold

// Top/bottom agents
top3 := tt.MostTrusted(3)
bots := tt.LeastTrusted(3)
```

## API

```go
// Create table
tt := fluxtrust.NewTrustTable()

// Config (or use DefaultConfig())
cfg := &fluxtrust.TrustConfig{
    NoneThreshold:    0.2,
    TrustedThreshold: 0.6,
    MaxTrust:         0.95,
    PositiveWeight:   0.1,
    NegativeWeight:   0.3,
    DecayPerHour:     0.01,
}

// Observations
tt.Observe(1, true, cfg, now)   // positive
tt.Observe(2, false, cfg, now)  // negative

// Queries
score := tt.Score(1)             // float64, -1 if unknown
trusted := tt.IsTrusted(1, cfg)  // bool
count := tt.Count()              // total agents tracked
nTrusted := tt.CountTrusted(cfg)

// Rankings
top := tt.MostTrusted(3)
bottom := tt.LeastTrusted(3)

// Management
tt.Revoke(1)                     // hard exclusion
tt.Decay(cfg, 24.0)              // decay over hours
```

### Config Parameters

| Param | Default | Effect |
|-------|---------|--------|
| PositiveWeight | 0.1 | Slow trust building |
| NegativeWeight | 0.3 | 3× faster distrust |
| DecayPerHour | 0.01 | ~0.24/day erosion |
| MaxTrust | 0.95 | Never 100% |

## Install

```bash
go get github.com/Lucineer/fluxtrust-go
```

## Fleet Context

Part of the Lucineer/Cocapn fleet. Go variant of [flux-trust](https://github.com/Lucineer/flux-trust) (Rust). Pairs with [fluxsocial-go](https://github.com/Lucineer/fluxsocial-go) and [fluxperception-go](https://github.com/Lucineer/fluxperception-go) for the full Go fleet stack.
