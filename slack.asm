BITS 64

default rel

%define SYS_read   0
%define SYS_write  1
%define SYS_exit   60

%define STDOUT     1

extern tls_init
extern tls_client_start

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

    ; initialize TLS subsystem (stub)
    call tls_init

    ; test start a client (stub) against a dummy fd (0)
    xor edi, edi                ; fd = 0 (stdin) -- placeholder
    lea rsi, [rel banner]       ; hostname pointer (placeholder)
    mov rdx, banner_len         ; hostname length
    call tls_client_start

    xor eax, eax
    ret

print_banner:
    mov eax, SYS_write
    mov edi, STDOUT
    lea rsi, [banner]
    mov edx, banner_len
    syscall
    ret
