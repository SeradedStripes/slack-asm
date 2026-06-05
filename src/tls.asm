BITS 64
default rel

section .text
global tls_init
global tls_client_start

t1:
    ret

; tls_init: initialize global TLS state
tls_init:
    ; placeholder
    ret

; tls_client_start(fd, hostname, hostlen)
; fd in edi, hostname -> rsi, hostlen -> rdx
tls_client_start:
    ; return success (0) (placeholder)
    xor eax, eax
    ret
