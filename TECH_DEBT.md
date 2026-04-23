# Technical Debt

veil 개발 과정에서 의도적으로 유예한 항목을 Phase별로 기록. 각 항목은 **원인 · 현재 영향 · 해소 방안**을 포함한다.

---

## Phase 1 — MVP 기능 완성

### 1.1 — config.zig

#### TD-1.1.1 Config 구조체에 arena 포인터 임베드 불가
- **원인**: Zig 0.15+의 `std.json`은 함수 포인터(`Allocator` vtable) 필드를 포함한 구조체 직접 파싱 불가.
- **현재 영향**: `Config`와 별도로 `Loaded { value, arena, parent_allocator }` wrapper 존재. 호출자는 `loaded.value.listen` 형태로 한 단계 더 돌아 접근.
- **상태**: **유예** (영향 작음 — 현 구조 유지).

### 1.3 — Upstream forwarding

#### TD-1.3.1 Connection pooling 없음 — **해소 (이번 세션)**
- **해결**: `src/pool.zig` 신규 (16 entries · 30s idle timeout · Wyhash-keyed spec matching). `pipeBidirectional`이 `.client_closed` / `.upstream_closed` 결과를 반환, 클라이언트가 깨끗이 닫고 업스트림이 idle(poll 0ms로 확인)일 때만 pool에 반납. 단일 스레드라 mutex 불필요. 단위 테스트 4개 포함.

#### TD-1.3.2 메시지 프레이밍 — **해소 (이번 세션)**
- **해결**: `src/frame.zig` 신규. 3가지 포맷 자동 감지:
  - `Content-Length: N\r\n\r\n<body>` (LSP, MCP stdio 표준)
  - NDJSON (`\n`-구분)
  - 대안 없으면 첫 청크를 단발 프레임으로 취급 (naive client 호환)
- 첫 감지 후 포맷 latch. `MAX_FRAME_BYTES=1 MiB`, `MAX_HEADER_BYTES=4 KiB`. 단위 테스트 7개.

### 1.4 — Listener 통합

#### TD-1.4.1 SIGTERM/SIGINT에서 Unix 소켓·PID 파일 잔존 — **해소 (Phase 3.1)**

### 1.5 — Upstream TLS

#### TD-1.5.1 단발 request/response 모델 (스트리밍 TLS 미지원)
- **원인**: `std.crypto.tls.Client` 는 Io.Reader/Writer pointer 참조에 stack buffer를 의존해 **인스턴스가 스코프 밖으로 이동하면 invalidate**. 또한 Reader/Writer가 공통 상태(transcript_hash, cipher state)를 공유해 thread-safe 아님. 결과:
  - pool에 TLS client 저장 불가 (lifetime 문제)
  - 2-threaded duplex (reader thread + writer thread) 불가 (thread-safety 문제)
- **현재 영향**: TLS 업스트림은 req/resp 1회만. persistent MCP 세션과 async notification은 plain TCP/Unix에서만 동작.
- **해소 방안** (대형 작업):
  1. TLS client + 버퍼를 heap 할당하여 lifetime 확장 → TLS pooling 가능
  2. TLS client API를 fork해 reader/writer 상태 분리 + mutex 추가 → duplex 가능
  3. stdlib std.crypto.tls가 thread-safe 대응 이후 채택
- **상태**: **유예** — MCP tool-call 용도로 현행 단발 모델이 실용적으로 충분. 스트리밍은 Phase 4+로.

#### TD-1.5.2 IP-only TLS는 `no_verification` — **해소 (이번 세션)**
- **해결**: `config.upstream_sni` 필드 추가 — `tls://IP:port` + SNI override로 엄격한 cert 검증 가능. 미지정 + IP 전용 tls://일 때 `veil start`/`validate`에서 명시적 WARNING 출력. 문서화된 "opt-in MITM 노출"로 전환.
- **잔존**: `config.upstream_ca_path` 필드는 스키마에 정의했으나 PEM 로딩은 미구현 (시스템 CA bundle만 사용). 필요 시 `std.crypto.Certificate.Bundle.addCertsFromFilePath` 연결.

#### TD-1.5.3 `allow_truncation_attacks = true` — **해소 (이번 세션)**
- **해결**: `config.upstream_tls_strict` 필드 추가. `true`면 `allow_truncation_attacks=false`. 기본 `false` (compat 우선) — Python ssl, 많은 raw TLS 서버가 close_notify 없이 종료하므로. 보안 요구 환경은 config로 enforce.

### 1.6 — PID 파일 기반 status

#### TD-1.6.1 PID 재사용 레이스 — **해소 (이번 세션)**
- **해결**: `pidfile.check` 가 `/proc/<pid>/comm`을 읽어 `"veil"`과 교차 검증. 다른 프로그램이 같은 PID를 재사용 중이면 `stale` 리포트. `/proc` 접근 불가 환경(sandbox)에선 `kill(pid,0)` 결과만 신뢰.

#### TD-1.6.2 파일 락 부재 — **해소 (이번 세션)**
- **해결**: `pidfile.acquireAndWrite` 가 `flock(LOCK_EX | LOCK_NB)` 잡은 채 PID 기록 → fd를 프로세스 수명 동안 보유 (커널이 exit 시 자동 해제). 동시 두 개 start → 두 번째는 `error.AlreadyRunning`.

---

## Phase 2 — 통합 테스트 & 빌드 강화

### 2.2 — Fuzz 테스트

#### TD-2.2.1 `zig build test --fuzz` 웹 UI 내부 크래시
- **원인**: Zig 0.15.2 `std/Build/Fuzz.zig:429` 내부 panic. upstream 버그.
- **상태**: **외부 차단** — Zig 0.16+ 또는 upstream fix 대기. 대체로 PRNG 기반 30,000건 property 테스트 유지.

### 2.1 — E2E 테스트

#### TD-2.1.1 TLS 업스트림 시나리오 미커버 — **해소 (이번 세션)**
- **해결**: `tests/e2e.zig`에 TLS 시나리오 추가 (`test "e2e(tls): allow forwards to TLS upstream"`). tmpdir에 `openssl req`로 self-signed cert 생성 → `python3 -u -c <script>`로 TLS echo 서버 기동 → veil이 `tls://127.0.0.1:PORT`로 forward → `TLS-ECHO:` 접두사 응답 검증. `openssl`/`python3` 미설치 시 자동 skip.

#### TD-2.1.2 Unix 소켓 listen·upstream 시나리오 미커버 — **해소 (이번 세션)**
- **해결**: `UnixUpstream` 헬퍼 + `setupUnixEnv`/`writeConfigUnix`/`sendAndReadUnix` 추가. `test "e2e(unix): allowed tool_call forwards to unix upstream"` + `"e2e(unix): blocked path denies without contacting upstream"`. 양방향 Unix 소켓(listen + upstream 모두 unix:) 검증.

#### TD-2.1.3 `Child.kill()` SIGTERM의존 — **해소 (Phase 3.1)**

---

## Phase 3 — 설정 UX

### 3.1 — 시그널 처리 & Hot-reload

#### TD-3.1.1 Retired config 메모리 누적 — **해소 (이번 세션)**
- **해결**: veil이 단일-스레드 accept 루프이므로 **reload가 실행되는 시점에는 이전 `handleConnection`이 모두 반환 완료**되어 있음. 이 불변식에 기반해 새 reload 시작 시 `retired` 리스트를 전부 `deinit` → `destroy`. 이전 retired 엔트리는 shutdown까지 기다릴 필요 없음. 매 SIGHUP마다 1개만 유지.

#### TD-3.1.2 Reload 시 listen/upstream 주소 재바인드 — **해소 (이번 세션)**
- **해결**: `ListenHandle { server, spec, unix_path }` 구조 도입. reload 후 `active.listen != listener.spec`이면 `rebindListener()` 호출 → 신규 spec으로 `ListenHandle.open` → 기존 fd 닫고 poll fds[0] 교체. Unix 경로는 기존 소켓 파일 unlink까지 처리. upstream 주소는 매 요청마다 `addr_mod.parse(cfg.upstream)` 하므로 자동 반영.

#### TD-3.1.3 Reload 후 rate_limiter 초기 설정 유지 — **해소 (이번 세션)**
- **해결**: `reload()` 끝에서 `state.rate_limiter.* = limiter.RateLimiter.init(new_rps, new_burst)`. 토큰은 새 burst로 리셋.

---

## 범위 밖(후속 메이저 작업)

- **Listen-side TLS**: stdlib TLS 서버가 약함. BearSSL 또는 std.crypto.tls 성숙 시 재평가.
- **HTTP/2 · SSE transport**: MCP HTTP 바인딩 대응. 현재는 raw JSON-RPC / LSP framing / NDJSON.
- **IPv6 listen/upstream**: `parseIpAndPort`는 IPv6 지원하지만 실제 E2E 미검증.
- **Windows/macOS 포팅**: 현재 Linux 전용 (`std.os.linux.getpid`, `/proc/<pid>/comm`, epoll-friendly poll 등).
- **Metrics/observability**: Prometheus-style counter(allow/deny/rate_limit/forward 수), 지연 히스토그램.
- **Streaming TLS** (TD-1.5.1): 메이저 아키텍처 변경 필요. 상세는 1.5.1 섹션.
- **Live config reload 중 connection drain**: hot-reload(3.1) 이후 기존 연결의 정책을 신규로 이관하려면 연결별 상태 트래킹 필요. 현재는 "새 연결부터 새 정책" 정책.
- **`upstream_ca_path` 구현**: config 필드는 정의됨 (TD-1.5.2), 로더 미구현.
