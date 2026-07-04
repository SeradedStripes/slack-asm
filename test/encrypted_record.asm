BITS 64
default rel

global run_encrypted_record_tests

extern tls_init, tls_derive_keys
extern hmac_sha256, aes128_cbc_encrypt, aes128_cbc_decrypt
extern client_write_key, client_write_mac_key
extern kdf_client_random, kdf_server_random
extern kdf_pre_master

%define TLS_APPLICATION_DATA 23
%define HS_DONE 3

section .text
run_encrypted_record_tests:
    push rbx
    sub rsp, 224
    ; [rsp+0] tls_ctx (118 bytes)
    ; [rsp+128] MAC output (32 bytes) / IV
    ; [rsp+160] padded plaintext (64 bytes) / mac_input

    lea rdi, [rsp]
    call tls_init

    lea rsi, [rel kdf_client_random]
    lea rdi, [rsp + 18]
    mov rcx, 32
    cld
    rep movsb

    lea rsi, [rel kdf_server_random]
    lea rdi, [rsp + 50]
    mov rcx, 32
    cld
    rep movsb

    lea rdi, [rsp]
    lea rsi, [rel kdf_pre_master]
    mov edx, 48
    call tls_derive_keys

    mov byte [rsp + 117], HS_DONE

    ; Build mac_input at rsp+160
    xor eax, eax
    mov qword [rsp + 160], 0
    mov byte [rsp + 168], TLS_APPLICATION_DATA
    mov byte [rsp + 169], 3
    mov byte [rsp + 170], 3
    mov byte [rsp + 171], 0
    mov byte [rsp + 172], 3
    mov byte [rsp + 173], 'a'
    mov byte [rsp + 174], 'b'
    mov byte [rsp + 175], 'c'

    lea rdi, [rel client_write_mac_key]
    mov rsi, 32
    lea rdx, [rsp + 160]
    mov rcx, 16
    lea r8, [rsp + 128]
    call hmac_sha256

    ; Build padded plaintext at rsp+160
    mov byte [rsp + 160], 'a'
    mov byte [rsp + 161], 'b'
    mov byte [rsp + 162], 'c'

    lea rdi, [rsp + 163]
    lea rsi, [rsp + 128]
    mov rcx, 32
    cld
    rep movsb

    mov ecx, 13
    mov al, 13
.pad:
    mov byte [rsp + 163 + 32 + rcx - 1], al
    dec ecx
    jnz .pad

    ; IV = zeros
    xor eax, eax
    mov qword [rsp + 128], rax
    mov qword [rsp + 136], rax

    lea rdi, [rel client_write_key]
    lea rsi, [rsp + 128]
    lea rdx, [rsp + 160]
    mov rcx, 48
    lea r8, [rsp + 160]
    call aes128_cbc_encrypt

    lea rdi, [rel client_write_key]
    lea rsi, [rsp + 128]
    lea rdx, [rsp + 160]
    mov rcx, 48
    lea r8, [rsp + 128]
    call aes128_cbc_decrypt

    lea rsi, [rsp + 128]
    add rsi, 48
    dec rsi
    movzx eax, byte [rsi]
    mov ecx, eax
    sub ecx, 48
    neg ecx

    cmp ecx, 35
    jne .fail

    cmp word [rsp + 128], 0x6261
    jne .fail
    cmp byte [rsp + 130], 0x63
    jne .fail

    add rsp, 224
    pop rbx
    xor eax, eax
    ret

.fail:
    add rsp, 224
    pop rbx
    mov eax, 1
    ret
