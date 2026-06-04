# slack-asm

A Slack bot written in **pure x86_64 Linux assembly**, no C, no Rust, no libc.

## Goals

- Speak **HTTP/1.1** over raw **Linux sockets** (syscalls only).
- **TLS** (≥1.2) implemented entirely in assembly, no OpenSSL, no libtls, no external crypto.
- Parse Slack's **WebSocket** [Events API](https://api.slack.com/apis/connections/socket) for real-time messaging.
- Handle Slack's OAuth & signing secrets for bot tokens.

## Why

Because it seemed like a good idea at the time.  
Now im doing it for [Stardance](https://stardance.hackclub.com/projects/6658).

## Status

Nothing yet. This is the init commit.

## Building

Requires:
- `nasm`
- `ld` (GNU ld)
- Linux x86_64

## Target

- **OS:** Linux (x86_64)
- **Syscall ABI:** `syscall` instruction, kernel calling convention
- **Calling convention:** System V AMD64 (for any interop, though there shouldn't be any)

## Project structure

```
slack.s          — entry point, main loop
http.s           — HTTP request/response parsing & serialization
tls/             — TLS 1.2/1.3 handshake & record layer (pure asm)
   handshake.s
   crypto.s
   record.s
socket.s         — socket(), connect(), send(), recv() wrappers
json.s           — minimal JSON parser (enough for Slack messages)
```

## Running the bot

Use the docker compose file..

## Running the code without docker

Run run.sh script.

## License

MIT License. See [LICENSE.md](LICENSE.md) for details.
