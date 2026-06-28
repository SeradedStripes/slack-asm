BITS 64
default rel

%define SYS_write  1
%define SYS_exit   60
%define STDOUT     1

extern tls_prf

section .rodata
secret:
    ; 48-byte PMS from captured connection
    db 0x03, 0x03, 0xcb, 0x63, 0x77, 0x25, 0xa5, 0xc7
    db 0x93, 0xd3, 0x19, 0xb5, 0x8b, 0x63, 0x2e, 0x7c
    db 0x04, 0xc3, 0x0a, 0x07, 0x46, 0x32, 0xa3, 0x90
    db 0x37, 0x47, 0x4e, 0xfc, 0x88, 0x10, 0x12, 0xf2
    db 0xc7, 0x77, 0x6c, 0x03, 0x68, 0xb6, 0xcc, 0xb7
    db 0x6b, 0x22, 0x95, 0x01, 0xf1, 0x11, 0xed, 0xcf
secret_len: equ $ - secret

client_random:
    db 0xd5, 0x5f, 0x1e, 0xf9, 0x55, 0x88, 0xf5, 0x6f
    db 0x81, 0x3a, 0xec, 0xde, 0x82, 0x9a, 0x7b, 0xda
    db 0x89, 0x0b, 0xaa, 0xc0, 0xe8, 0x9a, 0xa7, 0x81
    db 0x42, 0xcc, 0x8b, 0xca, 0x72, 0x0b, 0xbb, 0xf3
server_random:
    db 0x47, 0x85, 0x1d, 0xd5, 0x1b, 0xe5, 0x03, 0x38
    db 0x78, 0x8c, 0xfa, 0x1d, 0x4e, 0x0a, 0x20, 0x21
    db 0x5a, 0xb6, 0x92, 0xec, 0x42, 0x7a, 0xc7, 0x5c
    db 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01

master_label: db "master secret"
master_label_len: equ $ - master_label
key_expansion_label: db "key expansion"
key_expansion_label_len: equ $ - key_expansion_label
client_finished_label: db "client finished"
client_finished_label_len: equ $ - client_finished_label
server_finished_label: db "server finished"
server_finished_label_len: equ $ - server_finished_label

section .bss
seed_buf:   resb 128
master_buf: resb 48
key_block_buf: resb 96
out_buf:    resb 128

section .text
global _start
_start:
    xor ebp, ebp
    call main
    mov edi, eax
    mov eax, SYS_exit
    syscall

main:
    ; Test 1: Derive master secret
    ; Build seed = client_random + server_random
    lea rdi, [seed_buf]
    lea rsi, [client_random]
    mov rcx, 32
    cld
    rep movsb
    lea rsi, [server_random]
    mov rcx, 32
    rep movsb

    ; PRF(secret, "master secret", seed, master_buf, 48)
    lea rdi, [secret]
    mov rsi, secret_len
    lea rdx, [master_label]
    mov rcx, master_label_len
    lea r8, [seed_buf]
    mov r9, 64
    lea rax, [master_buf]
    push 48
    push rax
    call tls_prf
    add rsp, 16

    ; Write master secret
    mov eax, SYS_write
    mov edi, STDOUT
    lea rsi, [master_buf]
    mov edx, 48
    syscall

    ; Write newline
    mov byte [out_buf], 10
    mov eax, SYS_write
    mov edi, STDOUT
    lea rsi, [out_buf]
    mov edx, 1
    syscall

    ; Test 2: Derive key block
    ; Build seed = server_random + client_random
    lea rdi, [seed_buf]
    lea rsi, [server_random]
    mov rcx, 32
    cld
    rep movsb
    lea rsi, [client_random]
    mov rcx, 32
    rep movsb

    ; PRF(master_buf (master_secret), "key expansion", seed, key_block_buf, 96)
    lea rdi, [master_buf]
    mov rsi, 48
    lea rdx, [key_expansion_label]
    mov rcx, key_expansion_label_len
    lea r8, [seed_buf]
    mov r9, 64
    lea rax, [key_block_buf]
    push 96
    push rax
    call tls_prf
    add rsp, 16

    ; Write key block
    mov eax, SYS_write
    mov edi, STDOUT
    lea rsi, [key_block_buf]
    mov edx, 96
    syscall

    ; Write newline
    mov byte [out_buf], 10
    mov eax, SYS_write
    mov edi, STDOUT
    lea rsi, [out_buf]
    mov edx, 1
    syscall

    xor eax, eax
    ret
