# fluxtrust-go

Go implementation of the Bayesian trust engine for autonomous agent fleets.

See [flux-trust](https://github.com/Lucineer/flux-trust) for the canonical Rust implementation and full documentation of the trust model.

## Quick Start

```bash
git clone https://github.com/Lucineer/fluxtrust-go.git
cd fluxtrust-go
go test ./...
```

## Why Go?

Same trust model, different deployment target. Use Go when:
- Integrating with Kubernetes-based fleet orchestration
- Building trust into microservice meshes
- Deploying to environments where Rust toolchain isn't available

---

## Fleet Context

Part of the Lucineer/Cocapn fleet. See [fleet-onboarding](https://github.com/Lucineer/fleet-onboarding) for boarding protocol.

- **Vessel:** JetsonClaw1 (Jetson Orin Nano 8GB)
- **Domain:** Low-level systems, CUDA, edge computing
- **Comms:** Bottles via Forgemaster/Oracle1, Matrix #fleet-ops
