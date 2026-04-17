# veil

> A sub-50KB MCP sidecar proxy written in Zig. Zero dependencies. Zero overhead. Full protection.

**veil** sits between AI Agents and MCP servers, filtering every tool call through a minimal, auditable security layer. The entire binary fits in L1 cache.

## Why

Existing proxies (Envoy, nginx) are millions of lines of code with hundreds of dependencies. When your security gate is bigger than the thing it's protecting, the gate becomes the attack surface. veil takes the opposite approach: a binary so small you can read every instruction.

## Threat model

veil protects against:

- **Path traversal** — `file_read("/etc/passwd")` → blocked
- **Prompt injection via tool response** — patterns detected and stripped
- **Denial of service** — token bucket rate limiting per tool
- **Secret exfiltration** — outbound data checked against sensitive patterns
- **Unauthorized tool access** — explicit allowlist, deny by default

## Architecture

```
Agent ──► veil ──► MCP Server
         │
         ├─ Socket listener    (TCP / Unix domain)
         ├─ JSON parser        (zero-alloc streaming)
         ├─ Policy engine      (allowlist match, inline ASM hotpath)
         ├─ Rate limiter       (token bucket)
         ├─ Audit logger       (ring buffer, async write)
         └─ Forwarder          (passthrough or block)
```

## Specs (target)

| Metric | Target |
|--------|--------|
| Binary size | < 50 KB |
| Peak RSS | < 512 KB |
| Startup | < 1 ms |
| Latency added | < 50 μs per request |
| Dependencies | 0 (static musl) |

## Quick start

```bash
# Build
zig build -Doptimize=ReleaseSmall

# Run with default config
./zig-out/bin/veil --config config.json

# Check status
./zig-out/bin/veil status
```

## Configuration

```json
{
  "listen": "127.0.0.1:9000",
  "upstream": "127.0.0.1:3000",
  "policy": {
    "mode": "allowlist",
    "allowed_tools": ["file_read", "file_write", "shell_exec"],
    "blocked_paths": ["/etc/", "/root/", "~/.ssh/"],
    "blocked_patterns": ["password", "secret", "token", "api_key"],
    "rate_limit": {
      "requests_per_second": 100,
      "burst": 20
    }
  },
  "audit": {
    "enabled": true,
    "path": "/var/log/veil/audit.log",
    "max_size_mb": 10
  }
}
```

## Build

Requires Zig 0.13.0+.

```bash
# Debug build
zig build

# Release (optimized for size)
zig build -Doptimize=ReleaseSmall

# Run tests
zig build test

# Cross-compile for ARM
zig build -Doptimize=ReleaseSmall -Dtarget=aarch64-linux-musl
```

## Benchmarks

Coming soon. Will compare against:
- Direct connection (no proxy)
- Envoy sidecar
- nginx stream proxy

## Research context

veil is part of ongoing AI agent security research at Soongsil University AI Safety Research Center (ASC). It demonstrates that security layers for MCP/Agent communication can be added with near-zero performance cost when built from scratch with minimal trusted computing base.

Related work:
- [KIISC 2025] AI/ML vulnerability classification using source-to-sink analysis
- FIGS framework (Fine-grained Authorization, Identity, Guardrails, Sandboxing)
- CVE hunting on OpenClaw, vLLM, HuggingFace ecosystems

## License

MIT
