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

%define TLS_APPLICATION_DATA 23

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

    ; --- TLS record layer loopback test ---
    push rbx
    push rbp
    sub rsp, 96
    ; [rsp+0..3]   sv[0], sv[1]
    ; [rsp+8]      tls_ctx (18 bytes, padded)
    ; [rsp+40]     recv_type (1 byte)
    ; [rsp+48]     recv_len (8 bytes)
    ; [rsp+56]     recv_buf (40 bytes)

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
    lea rdx, [rsp + 40]     ; out_type
    lea rcx, [rsp + 56]     ; out_data
    lea r8, [rsp + 48]      ; out_len
    call tls_recv
    test eax, eax
    jnz .tls_fail

    ; Verify content type
    cmp byte [rsp + 40], TLS_APPLICATION_DATA
    jne .tls_fail

    ; Verify data length
    mov rax, [rsp + 48]
    cmp rax, test_input_len
    jne .tls_fail

    ; Verify data content
    lea rsi, [rsp + 56]
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

    add rsp, 96
    pop rbp
    pop rbx
    jmp .tls_pass

.tls_fail:
    add rsp, 96
    pop rbp
    pop rbx
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
