# Contributing to slack-asm

Thanks for helping improve this project. This short guide explains how to build, test, and contribute changes.

## Audience
This guide is intended for both AI agents and human contributors, please read with that context in mind.

## Assumptions

- This project targets Linux hosts. Use Linux tooling (nasm, ld, gdb, strace, qemu-user) when building and debugging.

## Build

Build the project using the `Makefile` targets:

```bash
make all
```

This produces the `slack` binary in the repository root.

## Running tests

Tests are exercised by running the compiled binary. Use the `test` target which builds then runs the binary:

```bash
make test
# or build and run directly
./slack
```

## Debugging

- For register/stack inspection use `gdb`:

```bash
gdb --args ./slack
```

- For syscalls and short traces use `strace`:

```bash
strace -f ./slack
```

- For cross-arch runs or emulation use `qemu-user` as needed.

## Commenting & style

- Follow the repository's Assembly commenting conventions described in `AGENTS.md`. (I know ironic a human needs to looks at AGENTS.md lol)
- Use `;` for comments, and place comments on their own line above or below the code they describe, never on the same line as executable code please.

## Tests and changes

- Add focused tests for any behaviour you change. Follow the `src/test.asm` style: test vectors in `.rodata`, buffers in `.bss`, deterministic comparisons using `repe cmpsb`, and clear pass/fail messages.
- Keep tests small and deterministic so local and CI runs are fast.

## Pull request checklist

- [ ] Tests added/updated and pass locally (`make test`).
- [ ] Commits are small and focused; tests included with the change.
  - (Quick Note, even if your commits are not small and focused, it will most likely still be merged, but please try to follow this guideline for easier reviews and better history.)
- [ ] Debug traces removed or clearly marked as test-only.

