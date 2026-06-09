# slack-asm

A Slack bot written in **pure x86_64 Linux assembly**, no C, no Rust, no libc.

## Overview

A slack bot written in pure x86_64 assembly!

### Features

(These are only the currently implemented ones, see the [roadmap](roadmap.md) for the full plan)

- Linux syscalls for networking (socket, connect, sendto, recvfrom).
- TLS 1.2 record layer and handshake (ClientHello → ServerHello + Cert + ServerHelloDone).
- SHA-256 and HMAC-SHA256 (all test vectors pass).
- Probably Something else, lets be honest im only reupdating this list when its convenient for me.

### Cool Things

- The comments tell you less info than the code.
- It probably has security issues, but they are not documented anywhere, so its fine!
- The code is not actually that bad, if you squint.

## Why

Because it seemed like a good idea at the time.  
Now im doing it for [Stardance](https://stardance.hackclub.com/projects/6658).

## Building

Requires:
- `make`
- `nasm`
- `ld` (GNU ld)
- Linux x86_64

```console
$ make
```

## Target

- **OS:** Linux (x86_64)
- **Syscall ABI:** `syscall` instruction, kernel calling convention
- **Calling convention:** System V AMD64 (for any interop, though there shouldn't be any)

## Running the bot

Use the docker compose file..

## Running the code without docker

Run run.sh script or do ./slack directly.

## License

MIT License. See [LICENSE.md](LICENSE.md) for details.
