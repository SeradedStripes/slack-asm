# Roadmap

## Phase 1: Skeleton

- Keep the entry point minimal and buildable.
- Set up a basic `main` flow.
- Reserve buffers and state for later networking and parsing.

## Phase 2: Linux Syscalls

- Wrap the syscalls we need:
  - `socket`
  - `connect`
  - `send`
  - `recv`
  - `close`
  - `exit`
- Add small helpers for error handling.

## Phase 3: TLS

- Implement the TLS record layer.
- Implement the handshake flow.
- Add the minimum crypto primitives needed for Slack connections.
- Verify certificate handling and server validation.

## Phase 4: HTTP

- Build HTTP request serialization.
- Build response parsing.
- Support Slack API calls over TLS.

## Phase 5: Slack Integration

- Authenticate with a bot token.
- Connect to Slack's real-time/event APIs.
- Parse incoming events.
- Send basic bot responses.

## Phase 6: Stability

- Reconnect on network failure.
- Handle rate limits and API errors.
- Add logging and diagnostics.
- Keep the binary small and dependency-free.

## Phase 7: Tooling

- Add CI for NASM builds.
- Add Docker-based build checks.
- Add a repeatable local run path.

## MVP

The first useful version should:

- Connect to Slack successfully.
- Receive one event.
- Send one response.
