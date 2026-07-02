# Roadmap

## [x] Phase 1: Skeleton
- Minimal entry point with a clean `main` flow.
- Reserve buffers and state for networking and parsing.
- Call a test harness to validate the environment.

## [x] Phase 2: Linux Syscalls
- Direct wrappers for `socket`, `connect`, `sendto`, `recvfrom`, `close`.
- Helpers for `sockaddr_in` construction and errno capture.

## [x] Phase 3: TLS
- [x] SHA-256 (pure assembly, tested with NIST vectors).
- [x] HMAC-SHA256 (all RFC 4231 test cases pass, including key > block-size branch).
- [x] TLS record layer (`tls_send`/`tls_recv`, plaintext + encrypted).
- [x] AES-128-CBC (encrypt/decrypt with PKCS#7 padding, MAC-then-encrypt).
- [x] AES-128-GCM with GHASH (GHASH unit-tested against Python `cryptography` library).
- [x] ECDHE key exchange (P-256, scalar mult + base-point mult, shared secret derivation).
- [x] TLS 1.2 handshake with `ECDHE-RSA-AES128-GCM-SHA256` (full sequence: CH → SH → Cert → SKE → SHD → CKE → CCS → Finished, server Finished verified).
- [x] RSA key exchange path (PMS encrypted with server RSA public key, fallback cipher suites).
- [x] Certificate parsing (DER/X.509), validity period check, RSA key extraction (modulus + exponent).
- [x] TLS PRF (P_SHA256) for master secret and key block derivation.
- [x] Transcript hash (SHA-256) for handshake integrity and Finished verify_data.
- [x] SNI (Server Name Indication) extension in ClientHello.
- [x] `tls_connect`/`tls_disconnect`/`tls_send`/`tls_recv` API.

## [x] Phase 4: HTTP
- [x] HTTP/1.1 request builder (method, path, headers, Content-Length, body).
- [x] HTTP response parser (status line, headers, Content-Length body, chunked transfer encoding).
- [x] Chunked transfer decoding (in-place, supports trailers, chunk extensions).
- [x] HTTPS integration: full round-trip against real servers (example.com via Cloudflare, local OpenSSL).

## [ ] Phase 5: Slack Integration
- [ ] Authenticate with a Slack bot token (OAuth, `Bot-Token` header).
- [ ] Call `apps.connections.open` to get a WebSocket URL.
- [ ] Parse Slack's Socket Mode WebSocket events (text frames, JSON payloads).
- [ ] Handle at least `message` events and echo a response.
- [ ] Conform to Slack's signing secret verification if needed.

## [ ] Phase 6: Robustness
- [ ] Reconnect on network/TLS failure with exponential backoff.
- [ ] Handle Slack rate limits (HTTP 429) and retry-After.
- [ ] Graceful shutdown on SIGTERM/SIGINT.
- [ ] Logging to stderr with timestamps.
- [ ] ENV file configuration for tokens and secrets.

## [ ] Phase 7: Polish & CI
- [x] Multi-stage Docker build (pure scratch image).
- [x] GitHub Actions CI for `docker build`.
- [x] Dependabot for GitHub Actions & Docker base image updates.
- [ ] Add smoke test step in CI.
- [ ] Track binary size across commits.
- [ ] Document environment variables and Slack app setup in README.

## MVP Definition
The first useful release will:
- Connect to Slack via Socket Mode.
- Receive one real event.
- Send one response back.

## Final Goal
- Scraping support
- More event types
- Auto reply to configured keywords
- Support for interactive components (buttons, modals)
- Auto reply to specific users or channels
- Support for slash commands
- Support for threads and message formatting
