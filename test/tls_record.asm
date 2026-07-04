BITS 64
default rel

global run_tls_record_tests

extern tls_init, tls_send, tls_recv
extern sys_socketpair, sys_close

section .rodata
test_input: db "abc"
test_input_len: equ $ - test_input

%define TLS_APPLICATION_DATA 23

section .text
run_tls_record_tests:
    push rbx
    push rbp
    sub rsp, 200
    ; [rsp+0..3]   sv[0], sv[1]
    ; [rsp+8]      tls_ctx (118 bytes)
    ; [rsp+128]    recv_type (1 byte)
    ; [rsp+136]    recv_len (8 bytes)
    ; [rsp+144]    recv_buf (40 bytes)

    lea rcx, [rsp]
    mov edi, 1
    mov esi, 1
    xor edx, edx
    call sys_socketpair
    test eax, eax
    jnz .fail

    mov ebx, [rsp]
    mov ebp, [rsp + 4]

    lea rdi, [rsp + 8]
    call tls_init

    lea rdi, [rsp + 8]
    mov esi, ebx
    mov edx, TLS_APPLICATION_DATA
    lea rcx, [rel test_input]
    mov r8, test_input_len
    call tls_send
    cmp rax, 0
    jl .fail

    lea rdi, [rsp + 8]
    mov esi, ebp
    lea rdx, [rsp + 128]
    lea rcx, [rsp + 144]
    lea r8, [rsp + 136]
    call tls_recv
    test eax, eax
    jnz .fail

    cmp byte [rsp + 128], TLS_APPLICATION_DATA
    jne .fail

    mov rax, [rsp + 136]
    cmp rax, test_input_len
    jne .fail

    lea rsi, [rsp + 144]
    lea rdi, [rel test_input]
    mov ecx, test_input_len
    cld
    repe cmpsb
    jnz .fail

    mov edi, ebx
    call sys_close
    mov edi, ebp
    call sys_close

    add rsp, 200
    pop rbp
    pop rbx
    xor eax, eax
    ret

.fail:
    mov edi, ebx
    call sys_close
    mov edi, ebp
    call sys_close
    add rsp, 200
    pop rbp
    pop rbx
    mov eax, 1
    ret
