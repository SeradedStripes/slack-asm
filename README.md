# slack-asm

A Slack bot written in **pure x86_64 Linux assembly**, no C, no Rust, no libc.

## Overview

A slack bot written in pure x86_64 assembly!

### Features

- a ping command (/slack-asm ping)
- a bing command (/slack-asm bing)
- a meow command (/slack-asm meow)
- a shameless plug command (/slack-asm shameless plug)
- a pung command (/slack-asm pung {user} [pings a person])
- a help command (/slack-asm help) - tis a help command bro

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

## License

MIT License. See [LICENSE.md](LICENSE.md) for details.
