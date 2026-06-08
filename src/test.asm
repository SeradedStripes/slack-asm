; Tests for various components of the libraries implemeted in the repo.

BITS 64
default rel

extern make_sockaddr_in
extern sys_socket
extern save_errno_and_ret
extern sys_close
extern sha256_init
extern sha256_update
extern sha256_final
extern hmac_sha256
extern tls_init
extern tls_send
extern tls_recv
extern sys_socketpair
extern sys_send
extern sys_recv
extern sys_close
extern tls_client_start
  extern tls_prf
  extern tls_derive_keys
  extern master_secret
  extern client_write_key
  extern server_write_key
  extern client_write_mac_key
  extern server_write_mac_key
  extern client_write_iv
  extern server_write_iv
  extern aes128_cbc_encrypt
  extern aes128_cbc_decrypt

%define TLS_APPLICATION_DATA 23
%define HS_DONE 3

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

; HMAC-SHA256 test case - RFC 4231 Test Case 1
hmac_key1:    times 20 db 0x0b
hmac_key1_len: equ $ - hmac_key1
hmac_msg1:    db "Hi There"
hmac_msg1_len: equ $ - hmac_msg1
hmac_expected1:
db 0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53
db 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b
db 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7
db 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7

; HMAC-SHA256 test case - RFC 4231 Test Case 2
hmac_key2:    db "Jefe"
hmac_key2_len: equ $ - hmac_key2
hmac_msg2:    db "what do ya want for nothing?"
hmac_msg2_len: equ $ - hmac_msg2
hmac_expected2:
db 0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e
db 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7
db 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83
db 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43

; HMAC-SHA256 test case - RFC 4231 Test Case 3
hmac_key3:    times 20 db 0xaa
hmac_key3_len: equ $ - hmac_key3
hmac_msg3:    times 50 db 0xdd
hmac_msg3_len: equ $ - hmac_msg3
hmac_expected3:
db 0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46
db 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7
db 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22
db 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe

; HMAC-SHA256 test case - RFC 4231 Test Case 4
hmac_key4:
db 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
db 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
db 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
db 0x19
hmac_key4_len: equ $ - hmac_key4
hmac_msg4:    times 50 db 0xcd
hmac_msg4_len: equ $ - hmac_msg4
hmac_expected4:
db 0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e
db 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a
db 0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07
db 0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b

; HMAC-SHA256 test case - RFC 4231 Test Case 5
hmac_key5:    times 20 db 0x0c
hmac_key5_len: equ $ - hmac_key5
hmac_msg5:    db "Test With Truncation"
hmac_msg5_len: equ $ - hmac_msg5
hmac_expected5:
db 0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0
db 0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55, 0x55, 0x2b
db 0xfa, 0x6f, 0x7c, 0x0a, 0x6a, 0x8a, 0xef, 0x8b
db 0x93, 0xf8, 0x60, 0xaa, 0xb0, 0xcd, 0x20, 0xc5

; HMAC-SHA256 test case - RFC 4231 Test Case 6 (key > 64 bytes, tests hash_key path)
hmac_key6:    times 131 db 0xaa
hmac_key6_len: equ $ - hmac_key6
hmac_msg6:    db "Test Using Larger Than Block-Size Key - Hash Key First"
hmac_msg6_len: equ $ - hmac_msg6
hmac_expected6:
db 0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f
db 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f
db 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14
db 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54

; HMAC-SHA256 test case - RFC 4231 Test Case 7 (key > 64, msg > 64)
hmac_key7:    times 131 db 0xaa
hmac_key7_len: equ $ - hmac_key7
hmac_msg7:    db "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
hmac_msg7_len: equ $ - hmac_msg7
hmac_expected7:
db 0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb
db 0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44
db 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93
db 0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2

; TLS server response for handshake test
; TLS Record: Handshake(22), version 0x0303, length 96
; Contains ServerHello + Certificate + ServerHelloDone
server_resp:
    ; TLS Record: Handshake(22), version 0x0303 (TLS 1.2), length 96
    db 0x16, 0x03, 0x03, 0x00, 0x60
    ; ServerHello (handshake msg type 2, body length 72)
    db 0x02, 0x00, 0x00, 72
    db 0x03, 0x03             ; version TLS 1.2
    ; server random of 32 Bytes
    db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    db 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    db 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    db 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    db 32                     ; session_id length
    times 32 db 0xaa          ; session_id
    db 0x00, 0x3C             ; cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA256
    db 0x00                   ; compression: null
    db 0x00, 0x00             ; extensions length: 0
    ; Certificate (handshake msg type 11, body length 12)
    db 0x0B, 0x00, 0x00, 12
    db 0x00, 0x00, 9          ; certificate list length
    db 0x00, 0x00, 6          ; cert[0] length
    db "CERT!!"               ; dummy certificate data
    ; ServerHelloDone (handshake msg type 14, body length 0)
    db 0x0E, 0x00, 0x00, 0
server_resp_end:
server_resp_len equ $ - server_resp

msg_pass:     db "all tests passed", 10
msg_pass_len: equ $ - msg_pass
msg_fail:     db "test failed", 10
msg_fail_len: equ $ - msg_fail

; PRF test vectors (from Python a reference)
prf_secret:      db "secret"
prf_secret_len:  equ $ - prf_secret
prf_label:       db "test label"
prf_label_len:   equ $ - prf_label
prf_seed:        db "seed1234"
prf_seed_len:    equ $ - prf_seed

prf_expected_32:
db 0x2c, 0x02, 0xf9, 0xaf, 0xb0, 0x8a, 0x8b, 0x4b
db 0x31, 0x25, 0x14, 0x13, 0xf8, 0x3d, 0xea, 0x67
db 0xa2, 0x71, 0x18, 0x0b, 0x42, 0xe7, 0x18, 0xac
db 0xfe, 0x24, 0x5f, 0x9e, 0xa7, 0x39, 0x4c, 0xe9

kdf_master_label: db "master secret"
kdf_master_label_len: equ $ - kdf_master_label
kdf_key_label:    db "key expansion"
kdf_key_label_len: equ $ - kdf_key_label

prf_expected_48:
db 0x2c, 0x02, 0xf9, 0xaf, 0xb0, 0x8a, 0x8b, 0x4b
db 0x31, 0x25, 0x14, 0x13, 0xf8, 0x3d, 0xea, 0x67
db 0xa2, 0x71, 0x18, 0x0b, 0x42, 0xe7, 0x18, 0xac
db 0xfe, 0x24, 0x5f, 0x9e, 0xa7, 0x39, 0x4c, 0xe9
db 0xd2, 0x74, 0x51, 0xb9, 0x2f, 0xb0, 0x7b, 0xaa
db 0x83, 0xcb, 0xf1, 0x7e, 0x10, 0x5c, 0x35, 0xf2

; Key derivation test vectors
kdf_client_random:
db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
db 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
db 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
db 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f

kdf_server_random:
db 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77
db 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
db 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87
db 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f

kdf_pre_master:
db 0x03, 0x03
db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
db 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
db 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
db 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
db 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
db 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
kdf_pre_master_len equ $ - kdf_pre_master

kdf_expected_ms:
db 0x62, 0xf0, 0xf1, 0x70, 0xf4, 0x2e, 0x10, 0xb1
db 0x0e, 0x0a, 0x56, 0xa3, 0xf9, 0x82, 0x8e, 0x3d
db 0x78, 0x97, 0xfa, 0x6e, 0x39, 0xbb, 0x53, 0x13
db 0xc2, 0x2b, 0x91, 0x10, 0x91, 0x36, 0x05, 0xbf
db 0x91, 0xbb, 0x5d, 0xc5, 0xde, 0x98, 0xd9, 0x5d
db 0xc6, 0x5a, 0xd1, 0xc1, 0xff, 0x6f, 0x3d, 0x48

kdf_expected_cwkey:
db 0x70, 0xbf, 0xd2, 0xdd, 0x0c, 0xb4, 0x0f, 0x62
db 0xab, 0xcd, 0x46, 0x38, 0xb4, 0xde, 0x22, 0x11

kdf_expected_swkey:
db 0xf4, 0x4b, 0x0b, 0x8f, 0x5a, 0x64, 0x94, 0x91
db 0x44, 0x10, 0x2e, 0xdf, 0xa4, 0x8d, 0x35, 0x6b

kdf_expected_a1:
db 0x52, 0xfc, 0x68, 0xb0, 0xfe, 0xe7, 0x03, 0xb3
db 0xe4, 0x9d, 0xcc, 0xdf, 0xd0, 0x0c, 0xb5, 0x80
db 0x43, 0x74, 0x73, 0x96, 0x57, 0xf9, 0xa5, 0x7a
db 0x23, 0x09, 0x82, 0xd9, 0xfe, 0x40, 0x85, 0x92

kdf_expected_iter1:
db 0x62, 0xf0, 0xf1, 0x70, 0xf4, 0x2e, 0x10, 0xb1
db 0x0e, 0x0a, 0x56, 0xa3, 0xf9, 0x82, 0x8e, 0x3d
db 0x78, 0x97, 0xfa, 0x6e, 0x39, 0xbb, 0x53, 0x13
db 0xc2, 0x2b, 0x91, 0x10, 0x91, 0x36, 0x05, 0xbf

kdf_expected_cwiv:
db 0x20, 0xf6, 0x84, 0x84

kdf_expected_swiv:
db 0x4f, 0x2a, 0x11, 0x29

prf_a1_expected:
db 0x7f, 0x10, 0xac, 0xcc, 0x13, 0xae, 0x22, 0x2f
db 0x8d, 0x23, 0x41, 0x33, 0x18, 0x29, 0xd5, 0x0b
db 0x32, 0x07, 0xae, 0x41, 0xf3, 0x9f, 0xe1, 0xdd
db 0x7a, 0x49, 0xb5, 0xad, 0xee, 0x7a, 0xf2, 0xc9

prf_a2_expected:
db 0x6f, 0x45, 0xb9, 0xd9, 0x33, 0x59, 0x71, 0x5e
db 0x8e, 0xd3, 0xde, 0x79, 0xc1, 0x4b, 0x6a, 0x68
db 0x40, 0x3b, 0x6d, 0x78, 0xb0, 0x4f, 0x4d, 0x2e
db 0x1e, 0xfa, 0xd1, 0xb8, 0x36, 0xc4, 0x6d, 0xd7

; AES-CBC test vectors (NIST AES-128-CBC)
aes_key:
db 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6
db 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
aes_iv:
db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
db 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
aes_plain:
db 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96
db 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
aes_expected:
db 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46
db 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d

section .bss
sha256_ctx: resb 104
digest:     resb 32
recv_buf:   resb 4096
prf_out:    resb 64
aes_cipher: resb 16
aes_decrypted: resb 16

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

    lea rdi, [hmac_key1]
    mov rsi, hmac_key1_len
    lea rdx, [hmac_msg1]
    mov rcx, hmac_msg1_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected1]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [hmac_key2]
    mov rsi, hmac_key2_len
    lea rdx, [hmac_msg2]
    mov rcx, hmac_msg2_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected2]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [hmac_key3]
    mov rsi, hmac_key3_len
    lea rdx, [hmac_msg3]
    mov rcx, hmac_msg3_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected3]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [hmac_key4]
    mov rsi, hmac_key4_len
    lea rdx, [hmac_msg4]
    mov rcx, hmac_msg4_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected4]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [hmac_key5]
    mov rsi, hmac_key5_len
    lea rdx, [hmac_msg5]
    mov rcx, hmac_msg5_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected5]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [hmac_key6]
    mov rsi, hmac_key6_len
    lea rdx, [hmac_msg6]
    mov rcx, hmac_msg6_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected6]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [hmac_key7]
    mov rsi, hmac_key7_len
    lea rdx, [hmac_msg7]
    mov rcx, hmac_msg7_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected7]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    ; --- PRF intermediate value tests ---
    ; Build seed_buf on stack = label + seed
    sub rsp, 128
    lea rdi, [rsp]
    lea rsi, [rel prf_label]
    mov rcx, prf_label_len
    cld
    rep movsb
    lea rsi, [rel prf_seed]
    mov rcx, prf_seed_len
    rep movsb

    ; Compute A(1) = HMAC(secret, seed_buf)
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
    jne .prf_abort

    ; Compute A(2) = HMAC(secret, A1)
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
    jne .prf_abort
    add rsp, 128
    jmp .prf_intermediate_ok

.prf_abort:
    add rsp, 128
    jmp .fail

.prf_intermediate_ok:

    ; --- PRF test ---
    ; --- Direct iteration 1 test ---
    ; This tests: iter1 = HMAC(secret, A(1) + seed_buf)
    sub rsp, 128

    ; Build seed_buf on stack
    lea rdi, [rsp]
    lea rsi, [rel prf_label]
    mov rcx, prf_label_len
    cld
    rep movsb
    lea rsi, [rel prf_seed]
    mov rcx, prf_seed_len
    rep movsb                     ; rsp[0..17] = seed_buf

    ; Compute A(1) = HMAC(secret, seed_buf)
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    mov rdx, rsp
    mov rcx, prf_label_len
    add rcx, prf_seed_len
    lea r8, [rsp + 32]           ; A(1) at rsp+32
    call hmac_sha256

    ; Build inbuf = A(1) + seed_buf at rsp+64
    lea rdi, [rsp + 64]
    lea rsi, [rsp + 32]
    mov rcx, 32
    rep movsb
    lea rsi, [rsp]
    mov rcx, prf_label_len
    add rcx, prf_seed_len        ; seed_buf_len
    rep movsb

    ; Compute iter1 = HMAC(secret, inbuf)
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    lea rdx, [rsp + 64]
    mov rcx, 32
    add rcx, prf_label_len
    add rcx, prf_seed_len        ; inbuf_len = 32 + seed_buf_len
    lea r8, [rsp + 96]           ; iter1 at rsp+96
    call hmac_sha256

    ; Compare iter1 with expected first 32 bytes
    lea rsi, [rsp + 96]
    lea rdi, [rel prf_expected_32]
    mov ecx, 32
    cld
    repe cmpsb
    jne .iter1_fail
    add rsp, 128
    jmp .iter1_ok
.iter1_fail:
    add rsp, 128
    jmp .fail
.iter1_ok:

    ; --- PRF 32-byte test via tls_prf ---
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    lea rdx, [rel prf_label]
    mov rcx, prf_label_len
    lea r8, [rel prf_seed]
    mov r9, prf_seed_len
    lea rax, [recv_buf]
    push 32
    push rax
    call tls_prf
    add rsp, 16

    lea rsi, [recv_buf]
    lea rdi, [rel prf_expected_32]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    ; --- PRF 33-byte test via tls_prf ---
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    lea rdx, [rel prf_label]
    mov rcx, prf_label_len
    lea r8, [rel prf_seed]
    mov r9, prf_seed_len
    lea rax, [recv_buf]
    push 33
    push rax
    call tls_prf
    add rsp, 16

    ; Check first 32 bytes
    lea rsi, [recv_buf]
    lea rdi, [rel prf_expected_32]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    ; --- PRF 48-byte test via tls_prf ---
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    lea rdx, [rel prf_label]
    mov rcx, prf_label_len
    lea r8, [rel prf_seed]
    mov r9, prf_seed_len
    lea rax, [recv_buf]
    push 48
    push rax
    call tls_prf
    add rsp, 16

    lea rsi, [recv_buf]
    lea rdi, [rel prf_expected_48]
    mov ecx, 48
    cld
    repe cmpsb
    jnz .fail

    ; --- Key derivation test: direct HMAC of seed_buf ---
    sub rsp, 128
    lea rdi, [rsp]
    lea rsi, [rel kdf_master_label]
    mov rcx, 13
    cld
    rep movsb
    lea rsi, [rel kdf_client_random]
    mov rcx, 32
    rep movsb
    lea rsi, [rel kdf_server_random]
    mov rcx, 32
    rep movsb       ; rsp[0..76] = seed_buf

    ; A(1) = HMAC(pre_master, seed_buf) into recv_buf
    lea rdi, [rel kdf_pre_master]
    mov rsi, kdf_pre_master_len
    mov rdx, rsp
    mov rcx, 77
    lea r8, [recv_buf]
    call hmac_sha256

    lea rsi, [recv_buf]
    lea rdi, [rel kdf_expected_a1]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .kdf_fail

    ; Build inbuf = A(1) + seed_buf at rsp
    lea rdi, [rsp]
    lea rsi, [recv_buf]
    mov rcx, 32
    cld
    rep movsb
    lea rsi, [rel kdf_master_label]
    mov rcx, 13
    rep movsb
    lea rsi, [rel kdf_client_random]
    mov rcx, 32
    rep movsb
    lea rsi, [rel kdf_server_random]
    mov rcx, 32
    rep movsb       ; rsp[0..108] = A(1)+seed_buf

    ; iter1 = HMAC(pre_master, inbuf) into recv_buf + 32
    lea rdi, [rel kdf_pre_master]
    mov rsi, kdf_pre_master_len
    mov rdx, rsp
    mov rcx, 109
    lea r8, [recv_buf + 32]
    call hmac_sha256

    lea rsi, [recv_buf + 32]
    lea rdi, [rel kdf_expected_iter1]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .kdf_fail

    add rsp, 128
    jmp .kdf_ok
.kdf_fail:
    add rsp, 128
    jmp .fail
.kdf_ok:

    ; --- TLS record layer loopback test ---
    push rbx
    push rbp
    sub rsp, 200
    ; [rsp+0..3]   sv[0], sv[1]
    ; [rsp+8]      tls_ctx (118 bytes)
    ; [rsp+128]    recv_type (1 byte)
    ; [rsp+136]    recv_len (8 bytes)
    ; [rsp+144]    recv_buf (40 bytes)

    ; Create socketpair (AF_UNIX, SOCK_STREAM, 0, sv)
    lea rcx, [rsp]
    mov edi, 1
    mov esi, 1
    xor edx, edx
    call sys_socketpair
    test eax, eax
    jnz .tls_fail

    mov ebx, [rsp]          ; sv[0] write end
    mov ebp, [rsp + 4]      ; sv[1] read end

    ; Initialize TLS context
    lea rdi, [rsp + 8]
    call tls_init

    ; Send "abc" as ApplicationData
    lea rdi, [rsp + 8]
    mov esi, ebx
    mov edx, TLS_APPLICATION_DATA
    lea rcx, [test_input]
    mov r8, test_input_len
    call tls_send
    cmp rax, 0
    jl .tls_fail

    ; Receive TLS record via tls_recv
    lea rdi, [rsp + 8]       ; ctx
    mov esi, ebp             ; fd = sv[1]
    lea rdx, [rsp + 128]    ; out_type
    lea rcx, [rsp + 144]    ; out_data
    lea r8, [rsp + 136]     ; out_len
    call tls_recv
    test eax, eax
    jnz .tls_fail

    ; Verify content type
    cmp byte [rsp + 128], TLS_APPLICATION_DATA
    jne .tls_fail

    ; Verify data length
    mov rax, [rsp + 136]
    cmp rax, test_input_len
    jne .tls_fail

    ; Verify data content
    lea rsi, [rsp + 144]
    lea rdi, [test_input]
    mov ecx, test_input_len
    cld
    repe cmpsb
    jnz .tls_fail

    ; Cleanup
    mov edi, ebx
    call sys_close
    mov edi, ebp
    call sys_close

    add rsp, 200
    pop rbp
    pop rbx

    ; --- TLS handshake test (fork based loopback) ---
    push rbx
    push rbp
    sub rsp, 144
    ; [rsp+0..3]   sv[0], sv[1]
    ; [rsp+8]      tls_ctx - 118 bytes
    ; [rsp+128]    child status - 4 bytes

    ; Create socketpair
    lea rcx, [rsp]
    mov edi, 1
    mov esi, 1
    xor edx, edx
    call sys_socketpair
    test eax, eax
    jnz .hs_fail

    mov ebx, [rsp]          ; sv[0] client end
    mov ebp, [rsp + 4]      ; sv[1] server end

    ; Fork
    mov eax, 57             ; SYS_fork
    syscall
    test eax, eax
    js .hs_fail             ; fork failed
    jnz .hs_parent

    ; --- Child process (TLS server) ---
    ; Close client end
    mov edi, ebx
    call sys_close

    ; Receive ClientHello
    mov edi, ebp
    lea rsi, [recv_buf]
    mov edx, 4096
    xor ecx, ecx
    call sys_recv

    ; Send server response
    mov edi, ebp
    lea rsi, [server_resp]
    mov edx, server_resp_len
    xor ecx, ecx
    call sys_send

    ; Close and exit
    mov edi, ebp
    call sys_close
    xor edi, edi
    mov eax, 60             ; SYS_exit
    syscall

.hs_parent:
    ; --- Parent process (TLS client) ---
    ; Close server end
    mov edi, ebp
    call sys_close

    ; Initialize TLS context
    lea rdi, [rsp + 8]
    call tls_init

    ; Run handshake
    lea rdi, [rsp + 8]      ; ctx
    mov esi, ebx            ; fd
    xor edx, edx            ; hostname = NULL
    xor ecx, ecx            ; hostlen = 0
    call tls_client_start
    test eax, eax
    jnz .hs_fail

    ; Verify handshake completed
    lea rdi, [rsp + 8]
    cmp byte [rdi + 117], HS_DONE            ; tls_ctx.hs_state
    jne .hs_fail

    ; Verify cipher suite was parsed (TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C)
    lea rdi, [rsp + 8]
    mov ax, [rdi + 115]            ; tls_ctx.cipher_suite
    cmp ax, 0x003C
    jne .hs_fail

    ; Verify session_id was parsed
    lea rdi, [rsp + 8]
    cmp byte [rdi + 114], 32        ; tls_ctx.session_id_len
    jne .hs_fail

    ; Wait for child to finish
    mov edi, -1              ; any child
    xor esi, esi             ; NULL status
    xor edx, edx             ; no options
    xor r10d, r10d           ; no rusage
    mov eax, 61              ; SYS_wait4
    syscall

    ; Cleanup
    mov edi, ebx
    call sys_close

    add rsp, 144
    pop rbp
    pop rbx
    jmp .after_hs

.hs_fail:
    add rsp, 144
    pop rbp
    pop rbx
    jmp .fail

.tls_fail:
    add rsp, 200
    pop rbp
    pop rbx
    jmp .fail

.after_hs:
    ; --- AES-CBC encrypt/decrypt round-trip test ---
    lea rdi, [rel aes_key]
    lea rsi, [rel aes_iv]
    lea rdx, [rel aes_plain]
    mov rcx, 16
    lea r8, [rel aes_cipher]
    call aes128_cbc_encrypt

    lea rsi, [rel aes_cipher]
    lea rdi, [rel aes_expected]
    mov ecx, 16
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [rel aes_key]
    lea rsi, [rel aes_iv]
    lea rdx, [rel aes_cipher]
    mov rcx, 16
    lea r8, [rel aes_decrypted]
    call aes128_cbc_decrypt

    lea rsi, [rel aes_decrypted]
    lea rdi, [rel aes_plain]
    mov ecx, 16
    cld
    repe cmpsb
    jnz .fail

    ; --- Encrypted TLS record test: build encrypted record in memory ---
    ; Set up TLS context and derive keys
    sub rsp, 224
    ; [rsp+0] tls_ctx (118 bytes)
    ; [rsp+128] MAC output (32 bytes)
    ; [rsp+160] padded plaintext (64 bytes)

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
    mov rdx, kdf_pre_master_len
    call tls_derive_keys

    mov byte [rsp + 117], HS_DONE

    ; Build mac_input at rsp+160 (seq||type||ver||len||frag)
    xor eax, eax
    mov qword [rsp + 160], 0  ; seq_num = 0 (8 bytes)
    mov byte [rsp + 168], TLS_APPLICATION_DATA
    mov byte [rsp + 169], 3   ; version major = 3
    mov byte [rsp + 170], 3   ; version minor = 3
    mov byte [rsp + 171], 0   ; fragment length high
    mov byte [rsp + 172], 3   ; fragment length low
    mov byte [rsp + 173], 'a'
    mov byte [rsp + 174], 'b'
    mov byte [rsp + 175], 'c'

    ; HMAC-SHA256(client_write_mac_key, 32, mac_input, 16, MAC_out at [rsp+128])
    lea rdi, [rel client_write_mac_key]
    mov rsi, 32
    lea rdx, [rsp + 160]
    mov rcx, 16
    lea r8, [rsp + 128]
    call hmac_sha256

    ; Build padded plaintext at rsp+160
    ; fragment "abc"
    mov byte [rsp + 160], 'a'
    mov byte [rsp + 161], 'b'
    mov byte [rsp + 162], 'c'

    ; Copy 32-byte MAC from rsp+128 to rsp+163
    lea rdi, [rsp + 163]
    lea rsi, [rsp + 128]
    mov rcx, 32
    cld
    rep movsb

    ; PKCS#7 padding: pad to 48 bytes (next multiple of 16 after 35)
    ; 48 - 35 = 13 bytes of 0x0d
    mov ecx, 13
    mov al, 13
.enc_pad:
    mov byte [rsp + 163 + 32 + rcx - 1], al
    dec ecx
    jnz .enc_pad

    ; Encrypt with AES-128-CBC
    ; Generate a dummy IV (16 bytes of zeros)
    xor eax, eax
    mov qword [rsp + 128], rax    ; reuse rsp+128 as IV area
    mov qword [rsp + 136], rax

    lea rdi, [rel client_write_key]
    lea rsi, [rsp + 128]          ; IV
    lea rdx, [rsp + 160]          ; plaintext (48 bytes)
    mov rcx, 48
    lea r8, [rsp + 160]           ; ciphertext output (in-place)
    call aes128_cbc_encrypt

    ; Decrypt with AES-128-CBC
    lea rdi, [rel client_write_key]
    lea rsi, [rsp + 128]          ; same IV
    lea rdx, [rsp + 160]          ; ciphertext
    mov rcx, 48
    lea r8, [rsp + 128]           ; decrypted output (reuse IV area)
    call aes128_cbc_decrypt

    ; Strip padding: last byte = pad value
    lea rsi, [rsp + 128]
    add rsi, 48
    dec rsi
    movzx eax, byte [rsi]         ; pad_value
    mov ecx, eax
    sub ecx, 48
    neg ecx                        ; ecx = unpadded length

    ; Verify unpadded length = 35 (3 fragment + 32 MAC)
    cmp ecx, 35
    jne .enc_fail

    ; Verify fragment "abc" (first 3 bytes)
    cmp word [rsp + 128], 0x6261            ; "ab"
    jne .enc_fail
    cmp byte [rsp + 130], 0x63              ; "c"
    jne .enc_fail

    add rsp, 224
    jmp .tls_pass

.enc_fail:
    add rsp, 224
    jmp .fail

.tls_pass:
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
