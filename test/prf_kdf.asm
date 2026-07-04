BITS 64
default rel

global run_prf_kdf_tests

extern hmac_sha256, tls_prf
extern kdf_pre_master, kdf_pre_master_len
extern kdf_client_random, kdf_server_random
extern kdf_master_label, kdf_key_label

section .rodata
; PRF test vectors
prf_secret:      db "secret"
prf_secret_len:  equ $ - prf_secret
prf_label:       db "test label"
prf_label_len:   equ $ - prf_label
prf_seed:        db "seed1234"
prf_seed_len:    equ $ - prf_seed

prf_expected_32:
db 0x2c,0x02,0xf9,0xaf,0xb0,0x8a,0x8b,0x4b
db 0x31,0x25,0x14,0x13,0xf8,0x3d,0xea,0x67
db 0xa2,0x71,0x18,0x0b,0x42,0xe7,0x18,0xac
db 0xfe,0x24,0x5f,0x9e,0xa7,0x39,0x4c,0xe9

prf_expected_48:
db 0x2c,0x02,0xf9,0xaf,0xb0,0x8a,0x8b,0x4b
db 0x31,0x25,0x14,0x13,0xf8,0x3d,0xea,0x67
db 0xa2,0x71,0x18,0x0b,0x42,0xe7,0x18,0xac
db 0xfe,0x24,0x5f,0x9e,0xa7,0x39,0x4c,0xe9
db 0xd2,0x74,0x51,0xb9,0x2f,0xb0,0x7b,0xaa
db 0x83,0xcb,0xf1,0x7e,0x10,0x5c,0x35,0xf2

prf_a1_expected:
db 0x7f,0x10,0xac,0xcc,0x13,0xae,0x22,0x2f
db 0x8d,0x23,0x41,0x33,0x18,0x29,0xd5,0x0b
db 0x32,0x07,0xae,0x41,0xf3,0x9f,0xe1,0xdd
db 0x7a,0x49,0xb5,0xad,0xee,0x7a,0xf2,0xc9

prf_a2_expected:
db 0x6f,0x45,0xb9,0xd9,0x33,0x59,0x71,0x5e
db 0x8e,0xd3,0xde,0x79,0xc1,0x4b,0x6a,0x68
db 0x40,0x3b,0x6d,0x78,0xb0,0x4f,0x4d,0x2e
db 0x1e,0xfa,0xd1,0xb8,0x36,0xc4,0x6d,0xd7

kdf_expected_a1:
db 0x44,0x59,0xfe,0xdc,0xcb,0xd2,0xf0,0xae
db 0x09,0x42,0xac,0xc5,0x00,0x87,0x18,0xc6
db 0xc6,0xdb,0xcf,0xd6,0xb7,0x44,0xb3,0xe8
db 0x5a,0x4d,0xdd,0xd7,0x74,0x00,0x1e,0x75

kdf_expected_iter1:
db 0xc7,0xb0,0x74,0xd9,0x7b,0x7d,0x02,0x02
db 0xff,0x9d,0xd8,0x8b,0xd8,0xa5,0xfc,0xa8
db 0x0e,0x4f,0xff,0x09,0xeb,0x8b,0xdf,0xbd
db 0x5c,0x79,0xf4,0x0e,0xfc,0x80,0xda,0x15

section .bss
buf:      resb 256

section .text
run_prf_kdf_tests:
    push rbx
    push r12
    sub rsp, 128

    ; PRF intermediate value test: A(1) = HMAC(secret, label+seed)
    lea rdi, [rsp]
    lea rsi, [rel prf_label]
    mov rcx, prf_label_len
    cld
    rep movsb
    lea rsi, [rel prf_seed]
    mov rcx, prf_seed_len
    rep movsb

    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    mov rdx, rsp
    mov rcx, prf_label_len
    add rcx, prf_seed_len
    lea r8, [rsp + 64]
    call hmac_sha256

    lea rsi, [rsp + 64]
    lea rdi, [rel prf_a1_expected]
    mov ecx, 32
    cld
    repe cmpsb
    jne .fail

    ; A(2) = HMAC(secret, A1)
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    lea rdx, [rsp + 64]
    mov rcx, 32
    lea r8, [rsp + 96]
    call hmac_sha256

    lea rsi, [rsp + 96]
    lea rdi, [rel prf_a2_expected]
    mov ecx, 32
    cld
    repe cmpsb
    jne .fail

    ; PRF direct iteration 1 test
    lea rdi, [rsp]
    lea rsi, [rel prf_label]
    mov rcx, prf_label_len
    cld
    rep movsb
    lea rsi, [rel prf_seed]
    mov rcx, prf_seed_len
    rep movsb

    ; A(1) = HMAC(secret, seed_buf)
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    mov rdx, rsp
    mov rcx, prf_label_len
    add rcx, prf_seed_len
    lea r8, [rsp + 32]
    call hmac_sha256

    ; Build inbuf = A(1) + seed_buf at rsp+64
    lea rdi, [rsp + 64]
    lea rsi, [rsp + 32]
    mov rcx, 32
    rep movsb
    lea rsi, [rsp]
    mov rcx, prf_label_len
    add rcx, prf_seed_len
    rep movsb

    ; iter1 = HMAC(secret, inbuf)
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    lea rdx, [rsp + 64]
    mov rcx, 32
    add rcx, prf_label_len
    add rcx, prf_seed_len
    lea r8, [rsp + 96]
    call hmac_sha256

    lea rsi, [rsp + 96]
    lea rdi, [rel prf_expected_32]
    mov ecx, 32
    cld
    repe cmpsb
    jne .fail

    ; PRF 32-byte via tls_prf
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    lea rdx, [rel prf_label]
    mov rcx, prf_label_len
    lea r8, [rel prf_seed]
    mov r9, prf_seed_len
    lea rax, [buf]
    push 32
    push rax
    call tls_prf
    add rsp, 16

    lea rsi, [buf]
    lea rdi, [rel prf_expected_32]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    ; PRF 48-byte via tls_prf
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    lea rdx, [rel prf_label]
    mov rcx, prf_label_len
    lea r8, [rel prf_seed]
    mov r9, prf_seed_len
    lea rax, [buf]
    push 48
    push rax
    call tls_prf
    add rsp, 16

    lea rsi, [buf]
    lea rdi, [rel prf_expected_48]
    mov ecx, 48
    cld
    repe cmpsb
    jnz .fail

    ; KDF: A(1) = HMAC(pre_master, label+client_random+server_random)
    lea rdi, [rsp]
    lea rsi, [kdf_master_label]
    mov rcx, 13
    cld
    rep movsb
    lea rsi, [kdf_client_random]
    mov rcx, 32
    rep movsb
    lea rsi, [kdf_server_random]
    mov rcx, 32
    rep movsb

    lea rdi, [kdf_pre_master]
    mov rsi, kdf_pre_master_len
    mov rdx, rsp
    mov rcx, 77
    lea r8, [buf]
    call hmac_sha256

    lea rsi, [buf]
    lea rdi, [rel kdf_expected_a1]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    ; Build inbuf = A(1) + seed_buf
    lea rdi, [rsp]
    lea rsi, [buf]
    mov rcx, 32
    cld
    rep movsb
    lea rsi, [kdf_master_label]
    mov rcx, 13
    rep movsb
    lea rsi, [kdf_client_random]
    mov rcx, 32
    rep movsb
    lea rsi, [kdf_server_random]
    mov rcx, 32
    rep movsb

    ; iter1 = HMAC(pre_master, inbuf) into buf+32
    lea rdi, [kdf_pre_master]
    mov rsi, kdf_pre_master_len
    mov rdx, rsp
    mov rcx, 109
    lea r8, [buf + 32]
    call hmac_sha256

    lea rsi, [buf + 32]
    lea rdi, [rel kdf_expected_iter1]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    add rsp, 128
    xor eax, eax
    pop r12
    pop rbx
    ret

.fail:
    add rsp, 128
    mov eax, 1
    pop r12
    pop rbx
    ret
