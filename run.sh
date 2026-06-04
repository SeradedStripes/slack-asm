#!/usr/bin/env bash
set -euo pipefail

nasm -f elf64 -o slack.o slack.s
ld -o slack slack.o

./slack
