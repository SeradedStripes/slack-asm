; The main entry point for slack-asm
; Phase 3+ integrates socket, TLS, crypto, and x509 layers.
;
; Intended flow for TLS-over-socket (Phase 4+):
;   fd = sys_socket(AF_INET, SOCK_STREAM, 0)
;   sys_connect(fd, &addr, 16)
;   tls_connect(&ctx, fd, hostname, hostlen)
;   tls_send(&ctx, fd, TLS_APPLICATION_DATA, data, len)
;   tls_recv(&ctx, fd, &type, buf, &buflen)
;   tls_disconnect(&ctx, fd)

BITS 64

default rel

%define SYS_write  1
%define SYS_exit   60

%define STDOUT     1

extern test_harness
extern tls_connect
extern tls_disconnect
extern sys_socket
extern sys_connect
extern sys_close
extern make_sockaddr_in

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

    ; Phase 3 integration: validate all layers end-to-end via test harness
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
