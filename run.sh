#!/usr/bin/env bash
set -euo pipefail

set -x

# assemble all .asm files into .o
for f in ./*.asm; do
  [ -e "$f" ] || continue
  obj="${f%%.asm}.o"
  nasm -f elf64 -o "$obj" "$f"
done

# link all object files
ld -o slack ./*.o

./slack
