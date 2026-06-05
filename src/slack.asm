BITS 64

default rel

%define SYS_read   0
%define SYS_write  1
%define SYS_exit   60

%define STDOUT     1

extern test_harness

section .rodata
banner:     db "slack-asm starting...", 10
banner_len: equ $ - banner

section .bss
; Scratch space for incoming HTTP/TLS traffic.
read_buf:   resb 4096

section .text
global _start

_start:
    xor ebp, ebp
    call main

    mov edi, eax
    mov eax, SYS_exit
    syscall

main:
    call print_banner

    ; run the small test harness which builds sockaddr and exercises errno handling
    call test_harness

    xor eax, eax
    ret

print_banner:
    mov eax, SYS_write
    mov edi, STDOUT
    lea rsi, [banner]
    mov edx, banner_len
    syscall
    ret
