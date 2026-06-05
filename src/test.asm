BITS 64
default rel

extern make_sockaddr_in
extern sys_socket
extern save_errno_and_ret
extern sys_close
extern sha256_init
extern sha256_update
extern sha256_final

section .rodata
sock_ok:       db "socket ok", 10
sock_ok_len:   equ $ - sock_ok
sock_fail:     db "socket failed", 10
sock_fail_len: equ $ - sock_fail

expected_empty:
db 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14
db 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24
db 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c
db 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55

expected_abc:
db 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea
db 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23
db 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c
db 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad

test_input:     db "abc"
test_input_len: equ $ - test_input

msg_pass:     db "all tests passed", 10
msg_pass_len: equ $ - msg_pass
msg_fail:     db "test failed", 10
msg_fail_len: equ $ - msg_fail

section .bss
sha256_ctx: resb 104
digest:     resb 32

section .text
global test_harness

test_harness:
    push rbx
    sub rsp, 32

    lea rdi, [rsp]
    mov esi, 80
    mov edx, 0x5DB8D822
    call make_sockaddr_in

    mov rdi, 2
    mov rsi, 1
    xor rdx, rdx
    call sys_socket

    call save_errno_and_ret
    cmp eax, -1
    je .socket_failed

    mov ebx, eax

    mov rax, 1
    mov rdi, 1
    lea rsi, [rel sock_ok]
    mov rdx, sock_ok_len
    syscall

    mov edi, ebx
    call sys_close

    add rsp, 32
    pop rbx

    lea rdi, [sha256_ctx]
    call sha256_init

    lea rdi, [sha256_ctx]
    lea rsi, [digest]
    call sha256_final

    lea rsi, [digest]
    lea rdi, [expected_empty]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [sha256_ctx]
    call sha256_init

    lea rdi, [sha256_ctx]
    lea rsi, [test_input]
    mov rdx, test_input_len
    call sha256_update

    lea rdi, [sha256_ctx]
    lea rsi, [digest]
    call sha256_final

    lea rsi, [digest]
    lea rdi, [expected_abc]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg_pass]
    mov rdx, msg_pass_len
    syscall
    jmp .done

.socket_failed:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel sock_fail]
    mov rdx, sock_fail_len
    syscall
    add rsp, 32
    pop rbx
    jmp .done

.fail:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg_fail]
    mov rdx, msg_fail_len
    syscall

.done:
    ret
