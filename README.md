# slack-asm

A Slack bot written in **pure x86_64 Linux assembly**, no C, no Rust, no libc.

## Overview

A slack bot written in pure x86_64 assembly!

(ARM support very very soon btw)

### Features

Commands can be triggered either as a slash command (`/slack-asm <cmd>`) or by pinging the bot (`@slack-asm <cmd>`).

- `ping` - replies `pong`.
- `bing` - replies `bong`.
- `meow` - meows back at you.
- `shameless plug` - a shameless plug.
- `pung {user}` - pings a person: `Get punged {user} :bleh:`.
- `help` - displays this help message.

### Cool Things

- The comments tell you less info than the code.
- It probably has security issues, but they are not documented anywhere, so its fine!
- The code is not actually that bad, if you squint.

## Why

Because it seemed like a good idea at the time.  
Now im doing it for [Stardance](https://stardance.hackclub.com/projects/6658).

## Slack App Setup

Create a Slack app at [api.slack.com/apps](https://api.slack.com/apps) and configure it as follows.

### 1. Socket Mode

Enable **Socket Mode** in the app settings.  
Create an app-level token with the `connections:write` scope (it starts with `xapp-`).

### 2. Event Subscriptions

Enable **Event Subscriptions** and subscribe to the bot events you want:

- `app_mention` - so pinging the bot (`@slack-asm`) triggers commands.
- `message.channels` / `message.im` / `message.groups` / `message.mpim` - for
  general message events.

### 3. Slash Commands

Create a slash command (e.g. `/slack-asm`) that points to your app.  
It can use the same Socket Mode connection for delivery.

### 4. Scopes & Installation

Add the bot token scope and install the app to your workspace.  
Copy the bot token (it starts with `xoxb-`).

### 5. Environment Variables

Provide the two tokens to the bot:

```sh
SLACK_TOKEN=xapp-......      # app-level token (Socket Mode)
SLACK_BOT_TOKEN=xoxb-......  # bot token
```

The bot reads them in this order of precedence:

1. A `.env` file in the working directory (see `.env.example`).
2. Process environment variables.
3. The first CLI argument (token only).

## Building

Requires:
- `make`
- `nasm`
- `ld` (GNU ld)
- Linux x86_64

```console
$ make
```

## Deployment

### Docker

The included `Dockerfile` builds the binary in an Alpine stage and produces a minimal `scratch` image:

```console
$ docker build -t slack-asm .
$ docker run --env-file .env slack-asm
```

Provide `SLACK_TOKEN` and `SLACK_BOT_TOKEN` as environment variables; they are not baked into the image.

**Side Note**: You can also use the prebuilt image `ghcr.io/seradedstripes/slack-asm:latest` if you don't want to build it yourself.

## Target

- **OS:** Linux (x86_64)
- **Syscall ABI:** `syscall` instruction, kernel calling convention
- **Calling convention:** System V AMD64 (for any interop, though there shouldn't be any)

## License

MIT License. See [LICENSE.md](LICENSE.md) for details.
