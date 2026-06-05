# Roadmap

## [x] Phase 1: Skeleton
- Minimal entry point with a clean `main` flow.
- Reserve buffers and state for networking and parsing.
- Call a test harness to validate the environment.

## [x] Phase 2: Linux Syscalls
- Direct wrappers for `socket`, `connect`, `sendto`, `recvfrom`, `close`.
- Helpers for `sockaddr_in` construction and errno capture.

## [ ] Phase 3: TLS (in progress)
- [ ] TLS record layer, specifically read/write TLSPlaintext records.
- [ ] TLS 1.2 handshake, specifically ClientHello → ServerHello + Cert + ServerHelloDone.
- [ ] TLS 1.3 support if required by Slack.
- [ ] Minimal crypto primitives: AES-CBC / AES-GCM, SHA-256, HMAC, key derivation.
- [ ] Certificate parsing (DER) and basic validation.
- [ ] Integrate with socket layer so all Slack traffic is tunneled over TLS.

## [ ] Phase 4: HTTP
- [ ] HTTP/1.1 request serialization (method, path, headers, body).
- [ ] HTTP response parsing (status line, headers, chunked/Content-Length body).
- [ ] Wire it to the TLS layer for `https://slack.com/api/*` calls. (I dont know if that api url is the correct one, but you get the idea)

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
