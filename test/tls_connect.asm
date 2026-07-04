BITS 64
default rel

global run_tls_connect_tests

extern tls_connect, tls_disconnect
extern sys_socketpair, sys_close, sys_send
extern _read_exactly
extern pre_master_sec

section .rodata
%define HS_DONE 3

extern rsa_n
extern kdf_pre_master, kdf_pre_master_len
extern cert_template_len_val, resp_total_len_val
extern cert_buf, server_resp_buf, recv_buf
extern _build_test_cert, _build_server_resp, _server_finish_handshake

section .text
run_tls_connect_tests:
    push rbx
    push rbp
    sub rsp, 144

    lea rcx, [rsp]
    mov edi, 1
    mov esi, 1
    xor edx, edx
    call sys_socketpair
    test eax, eax
    jnz .fail

    mov ebx, [rsp]
    mov ebp, [rsp + 4]

    lea rsi, [rel kdf_pre_master]
    lea rdi, [rel pre_master_sec]
    mov rcx, kdf_pre_master_len
    cld
    rep movsb

    lea rdi, [rel cert_buf]
    lea rsi, [rel rsa_n]
    call _build_test_cert
    lea rdi, [rel server_resp_buf]
    lea rsi, [rel cert_buf]
    mov edx, [rel cert_template_len_val]
    call _build_server_resp

    mov eax, 57
    syscall
    test eax, eax
    js .fail
    jnz .parent

    ; Child (TLS server)
    mov edi, ebx
    call sys_close

    mov edi, ebp
    lea rsi, [rel recv_buf]
    mov edx, 5
    call _read_exactly
    test eax, eax
    js .fail

    mov ax, [rel recv_buf + 3]
    ror ax, 8
    movzx r14d, ax

    mov edi, ebp
    lea rsi, [rel recv_buf + 5]
    mov edx, r14d
    call _read_exactly
    test eax, eax
    js .fail

    lea ebx, [r14d + 5]

    mov edi, ebp
    lea rsi, [rel server_resp_buf]
    mov edx, [rel resp_total_len_val]
    xor ecx, ecx
    call sys_send

    mov edi, ebp
    lea rsi, [rel recv_buf]
    mov edx, ebx
    call _server_finish_handshake

    mov edi, ebp
    call sys_close
    xor edi, edi
    mov eax, 60
    syscall

.parent:
    mov edi, ebp
    call sys_close

    lea rdi, [rsp + 8]
    mov esi, ebx
    xor edx, edx
    xor ecx, ecx
    call tls_connect
    test eax, eax
    jnz .fail

    cmp byte [rsp + 8 + 117], HS_DONE
    jne .fail

    mov ax, [rsp + 8 + 115]
    cmp ax, 0x003C
    jne .fail

    lea rdi, [rsp + 8]
    mov esi, ebx
    call tls_disconnect

    mov edi, -1
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall

    add rsp, 144
    pop rbp
    pop rbx
    xor eax, eax
    ret

.fail:
    add rsp, 144
    pop rbp
    pop rbx
    mov eax, 1
    ret
