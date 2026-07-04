BITS 64
default rel

extern make_sockaddr_in
extern sys_socket
extern sys_socketpair
extern sys_send
extern sys_recv
extern sys_close
extern _read_exactly
extern sha256_init, sha256_update, sha256_final
extern hmac_sha256
extern tls_init, tls_derive_keys, tls_prf
extern debug_hexdump
extern aes128_cbc_encrypt, aes128_cbc_decrypt
extern client_write_key, server_write_key
extern master_secret
extern client_write_mac_key, server_write_mac_key
extern tls_sha256_ctx, tls_digest
extern pre_master_sec

%define TLS_APPLICATION_DATA 23
%define HS_DONE 3
%define TLS_HANDSHAKE 22
%define TLS_CHANGE_CIPHER_SPEC 20
%define HS_FINISHED 20
%define FINISHED_LEN 12

section .rodata

; RSA-2048 public key for test cert
global rsa_n, rsa_e
rsa_n:
    db 0xb3,0x90,0xcb,0xa5,0xf2,0xca,0x05,0xfb
    db 0x39,0x69,0x5a,0x1f,0x48,0xb1,0xfe,0xff
    db 0x66,0x23,0x14,0xdc,0xd5,0x6a,0xf2,0x83
    db 0x5e,0x37,0x11,0x86,0xaa,0x81,0xed,0xea
    db 0x78,0x0d,0x51,0x8b,0x76,0x51,0xc9,0x4b
    db 0xba,0x89,0x8a,0x9e,0x94,0x1a,0x49,0xa1
    db 0xae,0x87,0x21,0x54,0xa2,0xaa,0x85,0xe4
    db 0x6a,0x47,0x2c,0x61,0xea,0x62,0xb1,0x19
    db 0xa2,0x3c,0xe9,0x46,0xd3,0x7b,0x55,0x75
    db 0x59,0x3f,0x80,0x53,0x8d,0xf9,0xa5,0xdd
    db 0x29,0xdc,0x3e,0x9b,0x48,0xa4,0x5b,0x66
    db 0xe1,0x38,0xd7,0x8c,0x31,0x0c,0x56,0x53
    db 0x47,0x6f,0x25,0x87,0xe2,0x1a,0x93,0xd9
    db 0x24,0xfa,0x7f,0x12,0x15,0x93,0x25,0xc6
    db 0x95,0x66,0x88,0xfb,0x35,0x1d,0x92,0xc0
    db 0xbd,0x05,0x1e,0x76,0xe4,0x54,0x32,0xe2
    db 0x93,0x51,0x37,0xc4,0x26,0xb0,0x68,0x8a
    db 0x9d,0xdd,0x22,0x98,0xce,0x07,0x23,0xa8
    db 0x3f,0x73,0x3e,0x4d,0x44,0xf0,0xd6,0x2d
    db 0x91,0x57,0x45,0x27,0x21,0x72,0x2f,0xc5
    db 0x70,0x25,0x0b,0xd4,0xa3,0x88,0x90,0x38
    db 0x45,0x66,0x5c,0x0f,0x75,0x37,0xf3,0x8c
    db 0x92,0x25,0x0f,0xa8,0x09,0xf8,0x64,0xa4
    db 0x3f,0x82,0x5e,0x96,0x8e,0x43,0xd7,0x75
    db 0x35,0x16,0xf6,0xd6,0x6a,0x0d,0x78,0x11
    db 0xda,0x36,0xca,0x38,0x1c,0x70,0x84,0x8a
    db 0x95,0x13,0xba,0x06,0xf0,0xae,0x9e,0xb5
    db 0xcf,0xb0,0x16,0x1a,0x5a,0x54,0x81,0x12
    db 0x22,0x53,0xcd,0x77,0x71,0xfe,0xfd,0x66
    db 0xb7,0x72,0x09,0xc2,0xa2,0x2c,0x8a,0xc8
    db 0x50,0xe2,0x47,0x2c,0xf3,0x68,0x81,0xe2
    db 0xdb,0xd1,0x32,0x3d,0x0c,0x94,0xc8,0x25
rsa_e:
    db 0x01, 0x00, 0x01

server_random:
    db 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
    db 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    db 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
    db 0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f

sh_body:
    db 0x03, 0x03
    db 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
    db 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    db 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
    db 0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    db 32
    times 32 db 0xaa
    db 0x00, 0x3C
    db 0x00
    db 0x00, 0x00

; Full DER X.509v3 certificate template with placeholder modulus
global cert_template, cert_template_len, cert_template_end
cert_template:
    db 0x30,0x82,0x02,0xa7,0x30,0x82,0x01,0x8f,0xa0,0x03,0x02,0x01,0x02,0x02,0x01,0x01
    db 0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b,0x05,0x00,0x30
    db 0x17,0x31,0x15,0x30,0x13,0x06,0x03,0x55,0x04,0x03,0x0c,0x0c,0x54,0x65,0x73,0x74
    db 0x20,0x52,0x6f,0x6f,0x74,0x20,0x43,0x41,0x30,0x1e,0x17,0x0d,0x32,0x34,0x30,0x31
    db 0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x17,0x0d,0x33,0x35,0x30,0x31,0x30
    db 0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x17,0x31,0x15,0x30,0x13,0x06,0x03
    db 0x55,0x04,0x03,0x0c,0x0c,0x54,0x65,0x73,0x74,0x20,0x52,0x6f,0x6f,0x74,0x20,0x43
    db 0x41,0x30,0x82,0x01,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01
    db 0x01,0x01,0x05,0x00,0x03,0x82,0x01,0x0f,0x00,0x30,0x82,0x01,0x0a,0x02,0x82,0x01
    db 0x01,0x00
    times 256 db 0x00
    db 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d
    db 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00
    times 256 db 0x00
cert_template_end:
cert_template_len equ cert_template_end - cert_template

sf_label:    db "server finished"
sf_label_len: equ $ - sf_label

; Offsets derived from cert size
CERT_OFFSET_IN_RESP equ 81
SHD_OFFSET_IN_RESP equ CERT_OFFSET_IN_RESP + 10 + cert_template_len
RESP_TOTAL_LEN equ SHD_OFFSET_IN_RESP + 4
CERT_HASH_LEN equ 10 + cert_template_len

section .rodata
debug_label_srv: db "SRV: ", 0

section .data
global cert_template_len_val, resp_total_len_val, cert_hash_len_val
cert_template_len_val: dd cert_template_len
resp_total_len_val:    dd RESP_TOTAL_LEN
cert_hash_len_val:     dd CERT_HASH_LEN

; KDF test vectors shared across TLS tests
global kdf_client_random, kdf_server_random, kdf_pre_master
global kdf_pre_master_len, kdf_master_label, kdf_key_label
kdf_client_random:
    db 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
    db 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    db 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
    db 0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
kdf_server_random:
    db 0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77
    db 0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f
    db 0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87
    db 0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f
kdf_pre_master:
    db 0x03, 0x03
    db 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
    db 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    db 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
    db 0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    db 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27
    db 0x28,0x29,0x2a,0x2b,0x2c,0x2d
kdf_pre_master_len equ $ - kdf_pre_master
kdf_master_label: db "master secret"
kdf_master_label_len: equ $ - kdf_master_label
kdf_key_label:    db "key expansion"
kdf_key_label_len: equ $ - kdf_key_label

section .bss
global recv_buf, cert_buf, server_resp_buf
recv_buf:   resb 4096
cert_buf:   resb 1024
server_resp_buf: resb 2048

section .text

; Build a runtime X.509v3 certificate
global _build_test_cert
_build_test_cert:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    lea rsi, [rel cert_template]
    mov rcx, cert_template_len
    rep movsb
    lea rdi, [rbx + 146]
    mov rsi, r12
    mov rcx, 256
    rep movsb
    mov rax, cert_template_len
    pop r13
    pop r12
    pop rbx
    ret

; Build a TLS record containing ServerHello + Certificate + ServerHelloDone
global _build_server_resp
_build_server_resp:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14d, edx
    mov byte [r12], 0x16
    mov word [r12 + 1], 0x0303
    lea eax, [r14d + 90]
    xchg ah, al
    mov [r12 + 3], ax
    lea rdi, [r12 + 5]
    mov byte [rdi], 2
    mov byte [rdi + 1], 0
    mov byte [rdi + 2], 0
    mov byte [rdi + 3], 72
    lea rsi, [rel sh_body]
    lea rdi, [rdi + 4]
    mov rcx, 72
    rep movsb
    lea rdi, [r12 + CERT_OFFSET_IN_RESP]
    mov byte [rdi], 0x0B
    mov eax, r14d
    add eax, 6
    mov byte [rdi + 3], al
    shr eax, 8
    mov byte [rdi + 2], al
    shr eax, 8
    mov byte [rdi + 1], al
    mov eax, r14d
    add eax, 3
    mov byte [rdi + 6], al
    shr eax, 8
    mov byte [rdi + 5], al
    shr eax, 8
    mov byte [rdi + 4], al
    mov eax, r14d
    mov byte [rdi + 9], al
    shr eax, 8
    mov byte [rdi + 8], al
    shr eax, 8
    mov byte [rdi + 7], al
    mov rsi, r13
    lea rdi, [rdi + 10]
    mov rcx, r14
    rep movsb
    lea rdi, [r12 + SHD_OFFSET_IN_RESP]
    mov dword [rdi], 0x0000000E
    mov eax, RESP_TOTAL_LEN
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Complete server-side handshake
global _server_finish_handshake
_server_finish_handshake:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 320
    mov r12d, edi
    mov r13, rsi
    mov r14d, edx
    lea rdi, [rsp]
    call tls_init
    lea rsi, [r13 + 11]
    lea rdi, [rsp + 18]
    mov rcx, 32
    cld
    rep movsb
    lea rsi, [rel server_resp_buf + 11]
    lea rdi, [rsp + 50]
    mov rcx, 32
    cld
    rep movsb
    lea rdi, [rsp]
    lea rsi, [rel kdf_pre_master]
    mov edx, kdf_pre_master_len
    call tls_derive_keys
    ; DEBUG: SRV writes
    mov rdi, 2
    lea rsi, [rel debug_label_srv]
    mov edx, 5
    mov eax, 1
    syscall
    lea rdi, [rel master_secret]
    mov esi, 16
    call debug_hexdump
    lea rdi, [rel client_write_key]
    mov esi, 16
    call debug_hexdump
    lea rdi, [rsp + 18]
    mov esi, 16
    call debug_hexdump
    lea rdi, [rsp + 50]
    mov esi, 16
    call debug_hexdump
    lea rdi, [rel kdf_pre_master]
    mov esi, 16
    call debug_hexdump
    lea rdi, [rel tls_sha256_ctx]
    call sha256_init
    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [r13 + 5]
    lea edx, [r14d - 5]
    call sha256_update
    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [rel server_resp_buf + 5]
    mov edx, 76
    call sha256_update
    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [rel server_resp_buf + CERT_OFFSET_IN_RESP]
    mov edx, CERT_HASH_LEN
    call sha256_update
    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [rel server_resp_buf + SHD_OFFSET_IN_RESP]
    mov edx, 4
    call sha256_update

    ; Receive CKE
    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 5
    call _read_exactly
    test eax, eax
    js .sfh_error
    cmp byte [rsp + 304], TLS_HANDSHAKE
    jne .sfh_error
    mov ax, [rsp + 307]
    ror ax, 8
    movzx r15d, ax
    mov edi, r12d
    lea rsi, [rel recv_buf]
    mov edx, r15d
    call _read_exactly
    test eax, eax
    js .sfh_error
    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [rel recv_buf]
    mov edx, r15d
    call sha256_update

    ; Receive CCS
    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 5
    call _read_exactly
    test eax, eax
    js .sfh_error
    cmp byte [rsp + 304], TLS_CHANGE_CIPHER_SPEC
    jne .sfh_error
    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 1
    call _read_exactly
    test eax, eax
    js .sfh_error
    cmp byte [rsp + 304], 1
    jne .sfh_error

    ; Receive client Finished
    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 5
    call _read_exactly
    test eax, eax
    js .sfh_error
    cmp byte [rsp + 304], TLS_HANDSHAKE
    jne .sfh_error
    mov ax, [rsp + 307]
    ror ax, 8
    movzx r15d, ax
    mov edi, r12d
    lea rsi, [rel recv_buf]
    mov edx, r15d
    call _read_exactly
    test eax, eax
    js .sfh_error
    cmp r15d, 17
    jb .sfh_error
    lea rdi, [rsp + 128]
    lea rsi, [rel recv_buf]
    mov rcx, 16
    cld
    rep movsb
    lea rdi, [rel client_write_key]
    lea rsi, [rsp + 128]
    lea rdx, [rel recv_buf + 16]
    mov ecx, r15d
    sub ecx, 16
    lea r8, [rel recv_buf + 16]
    call aes128_cbc_decrypt
    mov ecx, r15d
    sub ecx, 16
    lea rsi, [rel recv_buf + 16]
    add rsi, rcx
    dec rsi
    movzx eax, byte [rsi]
    mov eax, 16
    cmp eax, 16
    ja .sfh_error
    test eax, eax
    jz .sfh_error
    mov ebx, eax
    sub ecx, ebx
    sub ecx, 32
    js .sfh_error
    cmp byte [rel recv_buf + 16], HS_FINISHED
    jne .sfh_error
    mov edx, ecx
    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [rel recv_buf + 16]
    call sha256_update
    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [rel tls_digest]
    call sha256_final

    ; Compute server Finished verify_data
    lea rdi, [rel master_secret]
    mov esi, 48
    lea rdx, [rel sf_label]
    mov ecx, sf_label_len
    lea r8, [rel tls_digest]
    mov r9d, 32
    push 12
    lea rax, [rsp + 224 + 8]
    push rax
    call tls_prf
    add rsp, 16

    ; Send CCS
    mov byte [rsp + 304], TLS_CHANGE_CIPHER_SPEC
    mov word [rsp + 305], (3 << 8) | 3
    mov word [rsp + 307], 0x0100
    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 5
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .sfh_error
    mov byte [rsp + 304], 1
    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 1
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .sfh_error

    ; Build and send server Finished
    mov byte [rsp + 240], HS_FINISHED
    mov byte [rsp + 241], 0
    mov byte [rsp + 242], 0
    mov byte [rsp + 243], FINISHED_LEN
    lea rsi, [rsp + 224]
    lea rdi, [rsp + 244]
    mov rcx, FINISHED_LEN
    cld
    rep movsb
    mov rax, 0
    bswap rax
    mov qword [rsp + 144], rax
    mov byte [rsp + 152], TLS_HANDSHAKE
    mov word [rsp + 153], (3 << 8) | 3
    mov word [rsp + 155], 0x1000
    lea rdi, [rsp + 157]
    lea rsi, [rsp + 240]
    mov rcx, 16
    cld
    rep movsb
    lea rdi, [rel server_write_mac_key]
    mov rsi, 32
    lea rdx, [rsp + 144]
    mov rcx, 29
    lea r8, [rsp + 192]
    call hmac_sha256
    lea rdi, [rsp + 256]
    lea rsi, [rsp + 192]
    mov rcx, 32
    cld
    rep movsb
    lea rdi, [rsp + 240]
    add rdi, 48
    mov ecx, 16
    mov al, 15
    cld
    rep stosb
    mov byte [rsp + 304], TLS_HANDSHAKE
    mov word [rsp + 305], (3 << 8) | 3
    mov word [rsp + 307], 0x5000
    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 5
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .sfh_error
    mov edi, r12d
    lea rsi, [rsp + 128]
    mov edx, 16
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .sfh_error
    lea rdi, [rel server_write_key]
    lea rsi, [rsp + 128]
    lea rdx, [rsp + 240]
    mov ecx, 64
    lea r8, [rsp + 240]
    call aes128_cbc_encrypt
    mov edi, r12d
    lea rsi, [rsp + 240]
    mov edx, 64
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .sfh_error
    xor eax, eax
    add rsp, 320
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.sfh_error:
    mov eax, -1
    add rsp, 320
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
