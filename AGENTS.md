# Agents Guide for slack-asm

Purpose
-------
This document defines expectations, conventions, and required behaviours for automated AI agents (and contributors acting like agents) working on this repository.

Assumed environment: Linux
--------------------------
This guide assumes a Linux host for building, debugging and testing (tools and commands are Linux-focused).

Core rules
----------
- Follow the existing commenting style used in the assembly sources: use semicolons for comments and align comment blocks with surrounding code.
- Treat Assembly changes with extra care: debug thoroughly and add focused tests for any behaviour changed or added.
- When adding tests, follow the existing test format and harness style used in the repository (see [src/test.asm](src/test.asm)).
- Always request a human review when your work is complete. Do not proceed to further changes until an explicit human review has been completed and any requested follow-ups are acknowledged.

Commenting style (practical)
---------------------------
- Use `;` for comments (one full comment per line). Do not place comments on the same line as code; put the comment on the line above or the line below the code it describes. Prefer the line above.
- Keep comments short and factual; prefer describing intent over implementation details when possible.
- Match surrounding indentation and spacing conventions used in existing `.asm` files.

Debugging Assembly (required checklist)
--------------------------------------
When modifying or adding Assembly code, complete the following steps before requesting review:

1. Add or update unit tests that exercise the changed functionality using the repository's test harness pattern (labels, expected buffers, `test_harness`, printing pass/fail, etc.).
2. Reproduce failures locally by building the project and running the tests. Capture stderr/stdout and test outputs.
3. Isolate the smallest failing case: reduce inputs and create a focused test vector that fails deterministically.
4. Use low-level debugging tools where appropriate:
   - Run under `gdb` or an emulator (qemu-user) if reproducing on the host isn't possible.
   - Use breakpoints to inspect registers and stack at function entry/exit.
   - Add temporary, minimal `print`/write traces (keeping them gated behind test-only paths) to observe control flow and buffer contents.
5. Validate that all new memory allocations/reservations (resb/resw/etc.) match the required sizes and alignment.
6. Double-check calling conventions, register usage and preserved registers for all external symbols (externs).
7. Verify cryptographic test vectors (HMAC, SHA, AES, PRF) match known references and are included in tests.

Tests: format and expectations
-----------------------------
- Follow the style used in [src/test.asm](src/test.asm) for new tests: define test vectors in `.rodata`, reserve buffers in `.bss`, declare `extern` symbols, and add a `test_harness` entry (or integrate into it).
- Tests should compare buffers with `repe cmpsb` (or an equivalent deterministic comparison) and branch to a clear `.fail` label when mismatches occur.
- When a test is added for a bugfix, include a minimal reproduction vector and a passing expected value.
- Prefer adding test vectors that are deterministic and small to keep the test run fast and reliable.

Human Review requirement
------------------------
- After completing changes, the AI agent MUST explicitly request a human review and include:
  - What changed (files/labels affected).
  - How the change was tested (commands run and test output summaries).
  - Any remaining risks or open questions.
- The agent MUST NOT continue with unrelated modifications, merges, or wider refactors until a human confirms the review and either approves or requests further changes.

Working responsibly (best practices)
-----------------------------------
- Keep commits small and focused: one logical change per commit, include tests in the same commit when possible.
- Do not remove or silence existing tests without replacing them with equivalent coverage.
- Avoid speculative optimizations — prefer correctness and clarity.
- When unsure about subtle ABI/stack/register behaviour, ask for human guidance rather than guessing.

Notes
---------------------
- Assembly is unforgiving: small register or stack mistakes can cause cascading failures. Prioritize tiny, well-tested changes.
- Tests in this repository are already expressive; mirror their style exactly so CI / local runs remain predictable.
- Asking for a human review is critical — agents often miss edge cases in low-level code. Explicitly documenting test commands and observed output will make reviews fast and useful.
- This guide assumes Linux: recommended low-level debugging tools include `gdb`, `strace`, and `qemu-user` for cross-architecture runs. Use Linux syscall conventions and tools when diagnosing issues.

Quick checklist before submitting for review
-------------------------------------------
- [ ] Tests added/updated and pass locally.
- [ ] Small, focused commit(s) with explanatory messages.
- [ ] Debug traces removed or clearly marked test-only.
- [ ] Human review requested with test output and change summary.

If anything is unclear, stop and ask a human — don't guess.
