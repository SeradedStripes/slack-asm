; Crypto primitives: SHA-256 and HMAC-SHA256

BITS 64
default rel

SHA256_STATE  equ 0
SHA256_COUNT  equ 32
SHA256_BUFFER equ 40


section .rodata
align 16

sha256_k:
dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
dd 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
dd 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
dd 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
dd 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
dd 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

section .text
global sha256_init
global sha256_update
global sha256_final
global sha256_transform
global hmac_sha256

; sha256_init(void *ctx)
sha256_init:
    mov dword [rdi + 0],   0x6a09e667
    mov dword [rdi + 4],   0xbb67ae85
    mov dword [rdi + 8],   0x3c6ef372
    mov dword [rdi + 12],  0xa54ff53a
    mov dword [rdi + 16],  0x510e527f
    mov dword [rdi + 20],  0x9b05688c
    mov dword [rdi + 24],  0x1f83d9ab
    mov dword [rdi + 28],  0x5be0cd19
    xor eax, eax
    mov [rdi + 32], rax
    mov [rdi + 40], rax
    mov [rdi + 48], rax
    mov [rdi + 56], rax
    mov [rdi + 64], rax
    mov [rdi + 72], rax
    mov [rdi + 80], rax
    mov [rdi + 88], rax
    mov [rdi + 96], rax
    ret

; sha256_update(void *ctx, const void *data, uint64_t len)
sha256_update:
    test rdx, rdx
    jz .u_done

    push rbx
    push rbp
    push r12
    push r13

    mov r12, rdi
    mov r13, rsi
    mov rbp, rdx

    mov rax, [r12 + SHA256_COUNT]
    mov rbx, rax
    add rax, rbp
    mov [r12 + SHA256_COUNT], rax

    and ebx, 63
    jz .u_direct

    mov ecx, 64
    sub ecx, ebx
    cmp rbp, rcx
    jb .u_partial

    lea rdi, [r12 + SHA256_BUFFER + rbx]
    mov rsi, r13
    mov rdx, rcx
    call memcpy_internal
    mov rdi, r12
    lea rsi, [r12 + SHA256_BUFFER]
    call sha256_transform
    add r13, rcx
    sub rbp, rcx

.u_direct:
    mov rax, rbp
    shr rax, 6
    jz .u_tail
    mov rbx, rax

.u_block:
    mov rdi, r12
    mov rsi, r13
    call sha256_transform
    add r13, 64
    sub rbp, 64
    sub rbx, 1
    jnz .u_block

.u_tail:
    test ebp, ebp
    jz .u_exit
    lea rdi, [r12 + SHA256_BUFFER]
    mov rsi, r13
    mov rdx, rbp
    call memcpy_internal
    jmp .u_exit

.u_partial:
    lea rdi, [r12 + SHA256_BUFFER + rbx]
    mov rsi, r13
    mov rdx, rbp
    call memcpy_internal

.u_exit:
    pop r13
    pop r12
    pop rbp
    pop rbx
.u_done:
    ret

; sha256_final(void *ctx, void *digest)
sha256_final:
    push rbx
    push r12
    push r13

    mov r12, rdi
    mov r13, rsi

    mov rax, [r12 + SHA256_COUNT]
    mov ecx, eax
    and ecx, 63
    shl rax, 3
    mov rbx, rax

    mov byte [r12 + SHA256_BUFFER + rcx], 0x80
    inc ecx

    cmp ecx, 56
    jbe .f_fill

    mov edx, 64
    sub edx, ecx
    lea rdi, [r12 + SHA256_BUFFER + rcx]
    xor eax, eax
    mov rcx, rdx
    cld
    rep stosb

    mov rdi, r12
    lea rsi, [r12 + SHA256_BUFFER]
    call sha256_transform

    xor ecx, ecx

.f_fill:
    lea rdi, [r12 + SHA256_BUFFER + rcx]
    xor eax, eax
    mov edx, 56
    sub edx, ecx
    mov rcx, rdx
    cld
    rep stosb

    bswap rbx
    mov [r12 + SHA256_BUFFER + 56], rbx

    mov rdi, r12
    lea rsi, [r12 + SHA256_BUFFER]
    call sha256_transform

    mov ecx, 8
    lea rsi, [r12 + SHA256_STATE]
    mov rdi, r13
.f_emit:
    mov eax, [rsi]
    bswap eax
    mov [rdi], eax
    add rsi, 4
    add rdi, 4
    sub ecx, 1
    jnz .f_emit

    pop r13
    pop r12
    pop rbx
    ret

; sha256_transform(void *ctx, const void *block)
sha256_transform:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 272

    mov [rsp + 256], rdi
    mov [rsp + 264], rsi
    mov rbp, rsp

    xor ecx, ecx
.t_load:
    mov eax, [rsi + rcx*4]
    bswap eax
    mov [rbp + rcx*4], eax
    inc ecx
    cmp ecx, 16
    jb .t_load

    mov ecx, 16
.t_extend:
    mov eax, [rbp + rcx*4 - 8]
    mov ebx, eax
    ror ebx, 17
    mov edx, eax
    ror edx, 19
    shr eax, 10
    xor ebx, edx
    xor eax, ebx
    add eax, [rbp + rcx*4 - 28]
    mov ebx, [rbp + rcx*4 - 60]
    mov edx, ebx
    ror edx, 7
    mov edi, ebx
    ror edi, 18
    shr ebx, 3
    xor edx, edi
    xor ebx, edx
    add eax, ebx
    add eax, [rbp + rcx*4 - 64]
    mov [rbp + rcx*4], eax
    inc ecx
    cmp ecx, 64
    jb .t_extend

    mov rdi, [rsp + 256]
    mov r8d,  [rdi + 0]
    mov r9d,  [rdi + 4]
    mov r10d, [rdi + 8]
    mov r11d, [rdi + 12]
    mov r12d, [rdi + 16]
    mov r13d, [rdi + 20]
    mov r14d, [rdi + 24]
    mov r15d, [rdi + 28]

    lea rdi, [sha256_k]
    xor esi, esi

.t_round:
    mov eax, r12d
    ror eax, 6
    mov ebx, r12d
    ror ebx, 11
    xor eax, ebx
    mov ebx, r12d
    ror ebx, 25
    xor eax, ebx

    mov ebx, r12d
    and ebx, r13d
    mov ecx, r12d
    not ecx
    and ecx, r14d
    xor ebx, ecx

    add eax, ebx
    add eax, r15d
    add eax, [rdi + rsi*4]
    add eax, [rbp + rsi*4]

    mov ebx, r8d
    ror ebx, 2
    mov ecx, r8d
    ror ecx, 13
    xor ebx, ecx
    mov ecx, r8d
    ror ecx, 22
    xor ebx, ecx

    mov ecx, r8d
    and ecx, r9d
    mov edx, r8d
    and edx, r10d
    xor ecx, edx
    mov edx, r9d
    and edx, r10d
    xor ecx, edx

    add ebx, ecx
    mov r15d, r14d
    mov r14d, r13d
    mov r13d, r12d
    mov r12d, r11d
    add r12d, eax
    mov r11d, r10d
    mov r10d, r9d
    mov r9d, r8d
    add eax, ebx
    mov r8d, eax

    inc esi
    cmp esi, 64
    jb .t_round

    mov rdi, [rsp + 256]
    add [rdi + 0],  r8d
    add [rdi + 4],  r9d
    add [rdi + 8],  r10d
    add [rdi + 12], r11d
    add [rdi + 16], r12d
    add [rdi + 20], r13d
    add [rdi + 24], r14d
    add [rdi + 28], r15d

    add rsp, 272
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

memcpy_internal:
    mov rcx, rdx
    cld
    rep movsb
    ret

; hmac_sha256(const void *key, size_t key_len,
;            const void *msg, size_t msg_len,
;            void *mac)
; rdi=key, rsi=key_len, rdx=msg, rcx=msg_len, r8=mac
; More programming languages should have a commenting style like this
hmac_sha256:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 240

    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov [rsp + 232], r8

    lea rbp, [rsp]           ; rbp = K' buffer of 64 bytes

    cmp r13, 64
    ja .hash_key

    mov rdi, rbp
    mov rsi, r12
    mov rdx, r13
    call memcpy_internal

    mov rdi, rbp
    add rdi, r13
    mov rcx, 64
    sub rcx, r13
    xor eax, eax
    cld
    rep stosb
    jmp .xor_ipad

.hash_key:
    lea rdi, [rsp + 64]
    call sha256_init
    mov rdi, rsp
    add rdi, 64
    mov rsi, r12
    mov rdx, r13
    call sha256_update
    mov rdi, rsp
    add rdi, 64
    lea rsi, [rsp + 168]
    call sha256_final

    lea rdi, [rbp]
    lea rsi, [rsp + 168]
    mov rdx, 32
    call memcpy_internal
    xor eax, eax
    lea rdi, [rbp + 32]
    mov ecx, 32
    cld
    rep stosb

.xor_ipad:
    xor ecx, ecx
.xor_ipad_loop:
    mov rax, [rbp + rcx]
    mov rbx, 0x3636363636363636
    xor rax, rbx
    mov [rbp + rcx], rax
    add rcx, 8
    cmp rcx, 64
    jb .xor_ipad_loop

    lea rdi, [rsp + 64]
    call sha256_init
    mov rdi, rsp
    add rdi, 64
    mov rsi, rbp
    mov rdx, 64
    call sha256_update
    mov rdi, rsp
    add rdi, 64
    mov rsi, r14
    mov rdx, r15
    call sha256_update
    mov rdi, rsp
    add rdi, 64
    lea rsi, [rsp + 168]
    call sha256_final

    xor ecx, ecx
.xor_opad_loop:
    mov rax, [rbp + rcx]
    mov rbx, 0x6a6a6a6a6a6a6a6a
    xor rax, rbx
    mov [rbp + rcx], rax
    add rcx, 8
    cmp rcx, 64
    jb .xor_opad_loop

    lea rdi, [rsp + 64]
    call sha256_init
    mov rdi, rsp
    add rdi, 64
    mov rsi, rbp
    mov rdx, 64
    call sha256_update
    mov rdi, rsp
    add rdi, 64
    lea rsi, [rsp + 168]
    mov rdx, 32
    call sha256_update
    mov rdi, rsp
    add rdi, 64
    mov rsi, [rsp + 232]
    call sha256_final

    add rsp, 240
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; ============================================================
; AES-128-CBC (FIPS 197, RFC 5246)
; ============================================================

section .rodata

align 16
aes_sbox:
db 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5
db 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
db 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0
db 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
db 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc
db 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15
db 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a
db 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
db 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0
db 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84
db 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b
db 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf
db 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85
db 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8
db 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5
db 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2
db 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17
db 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73
db 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88
db 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb
db 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c
db 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79
db 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9
db 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08
db 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6
db 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a
db 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e
db 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e
db 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94
db 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
db 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68
db 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16

align 16
aes_inv_sbox:
db 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38
db 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
db 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87
db 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
db 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d
db 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
db 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2
db 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
db 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16
db 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
db 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda
db 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
db 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a
db 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
db 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02
db 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
db 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea
db 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
db 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85
db 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
db 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89
db 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
db 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20
db 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
db 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31
db 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
db 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d
db 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
db 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0
db 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
db 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26
db 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d

align 16
aes_rcon: db 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36

section .text
global aes128_key_expand
global aes128_encrypt_block
global aes128_decrypt_block
global aes128_cbc_encrypt
global aes128_cbc_decrypt

; void aes128_key_expand(const void *key, void *round_keys)
; rdi = key (16 bytes), rsi = round_keys (176 bytes output)
aes128_key_expand:
    push rbx
    push r12

    ; Copy first 4 words directly from key
    mov rax, [rdi]
    mov [rsi], rax
    mov rax, [rdi + 8]
    mov [rsi + 8], rax

    xor r12d, r12d           ; rcon index
    mov ecx, 4               ; word index

.ke_loop:
    ; temp = word[i-1]
    mov eax, [rsi + rcx*4 - 4]

    test cl, 3               ; if (i % 4 == 0) ?
    jnz .ke_no_rot

    ; RotWord: rotate left by 1 byte (ror on LE x86 = RotWord in AES)
    ror eax, 8

    ; SubWord: apply S-box to each byte
    movzx ebx, al
    movzx ebx, byte [aes_sbox + rbx]
    movzx edx, ah
    movzx edx, byte [aes_sbox + rdx]
    shl edx, 8
    or ebx, edx
    shr eax, 16
    movzx edx, al
    movzx edx, byte [aes_sbox + rdx]
    shl edx, 16
    or ebx, edx
    movzx edx, ah
    movzx edx, byte [aes_sbox + rdx]
    shl edx, 24
    mov eax, ebx
    or eax, edx

    ; XOR with Rcon[rcon_index]
    movzx ebx, byte [aes_rcon + r12]
    xor al, bl
    inc r12d

.ke_no_rot:
    ; word[i] = word[i-4] XOR temp
    mov ebx, [rsi + rcx*4 - 16]
    xor eax, ebx
    mov [rsi + rcx*4], eax

    inc ecx
    cmp ecx, 44
    jb .ke_loop

    pop r12
    pop rbx
    ret

; static void _sub_bytes(void *state)
; rdi = state (16 bytes)
_sub_bytes:
    push rbx
    xor ecx, ecx
.sb_loop:
    movzx eax, byte [rdi + rcx]
    movzx eax, byte [aes_sbox + rax]
    mov [rdi + rcx], al
    inc ecx
    cmp ecx, 16
    jb .sb_loop
    pop rbx
    ret

; static void _inv_sub_bytes(void *state)
_inv_sub_bytes:
    push rbx
    xor ecx, ecx
.isb_loop:
    movzx eax, byte [rdi + rcx]
    movzx eax, byte [aes_inv_sbox + rax]
    mov [rdi + rcx], al
    inc ecx
    cmp ecx, 16
    jb .isb_loop
    pop rbx
    ret

; static void _shift_rows(void *state)
; AES state is column-major: state[col*4 + row]
; Row 0: offsets 0, 4, 8, 12  — no shift
; Row 1: offsets 1, 5, 9, 13  — shift left 1
; Row 2: offsets 2, 6, 10, 14 — shift left 2
; Row 3: offsets 3, 7, 11, 15 — shift left 3
_shift_rows:
    push rbx
    ; Row 1: [1,5,9,13] ← [5,9,13,1]
    movzx eax, byte [rdi + 5]
    movzx ebx, byte [rdi + 9]
    movzx ecx, byte [rdi + 13]
    movzx edx, byte [rdi + 1]
    mov byte [rdi + 1], al
    mov byte [rdi + 5], bl
    mov byte [rdi + 9], cl
    mov byte [rdi + 13], dl
    ; Row 2: [2,6,10,14] ← [10,14,2,6]  (shift left 2)
    movzx eax, byte [rdi + 10]
    movzx ebx, byte [rdi + 14]
    movzx ecx, byte [rdi + 2]
    movzx edx, byte [rdi + 6]
    mov byte [rdi + 2], al
    mov byte [rdi + 6], bl
    mov byte [rdi + 10], cl
    mov byte [rdi + 14], dl
    ; Row 3: [3,7,11,15] ← [15,3,7,11]  (shift left 3 = right 1)
    movzx eax, byte [rdi + 15]
    movzx ebx, byte [rdi + 3]
    movzx ecx, byte [rdi + 7]
    movzx edx, byte [rdi + 11]
    mov byte [rdi + 3], al
    mov byte [rdi + 7], bl
    mov byte [rdi + 11], cl
    mov byte [rdi + 15], dl
    pop rbx
    ret

; static void _inv_shift_rows(void *state)
; Row 1: shift right 1 = [1,5,9,13] ← [13,1,5,9]
; Row 2: shift right 2 = [2,6,10,14] ← [6,10,14,2] (already correct: shift left 2 reversed)
; Actually: inv shift right 1 = left 3, etc.
; Row 1: left shift original, so inv = right shift 1: [1,5,9,13] ← [13,1,5,9]
; Row 2: left shift 2, inv = right shift 2: [2,6,10,14] ← [14,2,6,10]?? 
; Wait, let me think again.
; Forward: Row 1: [1,5,9,13] → [5,9,13,1] (left 1)
; Inverse: Row 1: [5,9,13,1] → [1,5,9,13] (right 1) = [1,5,9,13] ← [13,1,5,9]
;   So: new[1]=old[13], new[5]=old[1], new[9]=old[5], new[13]=old[9]
; Forward: Row 2: [2,6,10,14] → [10,14,2,6] (left 2)
; Inverse: Row 2: [10,14,2,6] → [2,6,10,14] (right 2) = [2,6,10,14] ← [10,14,2,6]
;   So: new[2]=old[10], new[6]=old[14], new[10]=old[2], new[14]=old[6]
; But that's the same mapping as forward shift left 2!
; Actually it's symmetric for shift 2: left2 and right2 are the same.
; Forward: Row 3: [3,7,11,15] → [15,3,7,11] (left 3)
; Inverse: Row 3: [15,3,7,11] → [3,7,11,15] (right 3 = left 1)
;   So: new[3]=old[7], new[7]=old[11], new[11]=old[15], new[15]=old[3]
_inv_shift_rows:
    push rbx
    ; Row 1 (inv right 1): [1,5,9,13] ← [13,1,5,9]
    movzx eax, byte [rdi + 13]
    movzx ebx, byte [rdi + 1]
    movzx ecx, byte [rdi + 5]
    movzx edx, byte [rdi + 9]
    mov byte [rdi + 1], al
    mov byte [rdi + 5], bl
    mov byte [rdi + 9], cl
    mov byte [rdi + 13], dl
    ; Row 2 (inv right 2): [2,6,10,14] ← [10,14,2,6]
    ; Same as left 2, which is its own inverse
    movzx eax, byte [rdi + 10]
    movzx ebx, byte [rdi + 14]
    movzx ecx, byte [rdi + 2]
    movzx edx, byte [rdi + 6]
    mov byte [rdi + 2], al
    mov byte [rdi + 6], bl
    mov byte [rdi + 10], cl
    mov byte [rdi + 14], dl
    ; Row 3 (inv right 3 = left 1): [3,7,11,15] ← [7,11,15,3]
    movzx eax, byte [rdi + 7]
    movzx ebx, byte [rdi + 11]
    movzx ecx, byte [rdi + 15]
    movzx edx, byte [rdi + 3]
    mov byte [rdi + 3], al
    mov byte [rdi + 7], bl
    mov byte [rdi + 11], cl
    mov byte [rdi + 15], dl
    pop rbx
    ret

; static uint8_t _xtime(uint8_t x)
; al = x, returns al = 2*x in GF(2^8)
_xtime:
    push rbx
    mov bl, al
    shl al, 1
    test bl, 0x80
    jz .x_done
    xor al, 0x1b
.x_done:
    pop rbx
    ret

; static void _mix_columns(void *state)
_mix_columns:
    push rbx
    push r12
    push r13
    push r14
    push r15

    xor r12d, r12d            ; column index
.mc_col:
    ; Load column (4 contiguous bytes)
    movzx r13d, byte [rdi + r12*4]      ; a = s[0, r12]
    movzx r14d, byte [rdi + r12*4 + 1]  ; b = s[1, r12]
    movzx r15d, byte [rdi + r12*4 + 2]  ; c = s[2, r12]
    movzx ebx,  byte [rdi + r12*4 + 3]  ; d = s[3, r12]

    ; Compute tmp = a XOR b XOR c XOR d
    mov eax, r13d
    xor eax, r14d
    xor eax, r15d
    xor eax, ebx                        ; eax = tmp

    ; Compute xtime(a XOR b)
    mov ecx, r13d
    xor ecx, r14d
    mov al, cl
    call _xtime                        ; al = xtime(a ^ b)
    mov ecx, eax

    ; XOR with xtime(c XOR d)
    mov eax, r15d
    xor eax, ebx
    call _xtime
    xor ecx, eax                       ; ecx = xtime(a^b) ^ xtime(c^d)

    ; Now compute each output byte
    ; out_a = xtime(a) ^ xtime(b) ^ b ^ c ^ d
    ;       = xtime(a) ^ xtime(b) ^ tmp ^ b
    ;       = (xtime(a) ^ a) ^ (xtime(b) ^ b) ^ tmp
    ; We'll do it directly:
    ; out_a = (2*a) ^ (3*b) ^ c ^ d
    ; out_b = a ^ (2*b) ^ (3*c) ^ d
    ; out_c = a ^ b ^ (2*c) ^ (3*d)
    ; out_d = (3*a) ^ b ^ c ^ (2*d)
    ; Where (3*x) = (2*x) ^ x

    ; out_a = (2*a) ^ (3*b) ^ c ^ d
    mov eax, r13d
    call _xtime
    push rax                          ; 2*a
    mov eax, r14d
    call _xtime
    xor eax, r14d                     ; 3*b
    pop rcx
    xor eax, ecx                      ; 2*a ^ 3*b
    xor eax, r15d                     ; ^ c
    xor eax, ebx                      ; ^ d
    mov byte [rdi + r12*4], al

    ; out_b = a ^ (2*b) ^ (3*c) ^ d
    mov eax, r14d
    call _xtime
    xor eax, r13d                     ; a ^ 2*b
    push rax
    mov eax, r15d
    call _xtime
    xor eax, r15d                     ; 3*c
    pop rcx
    xor eax, ecx
    xor eax, ebx                      ; ^ d
    mov byte [rdi + r12*4 + 1], al

    ; out_c = a ^ b ^ (2*c) ^ (3*d)
    mov eax, r15d
    call _xtime
    xor eax, r13d                     ; a ^ 2*c
    push rax
    mov eax, ebx
    call _xtime
    xor eax, ebx                      ; 3*d
    pop rcx
    xor eax, ecx
    xor eax, r14d                     ; ^ b
    mov byte [rdi + r12*4 + 2], al

    ; out_d = (3*a) ^ b ^ c ^ (2*d)
    mov eax, r13d
    call _xtime
    xor eax, r13d                     ; 3*a
    push rax
    mov eax, ebx
    call _xtime                       ; 2*d
    pop rcx
    xor eax, ecx
    xor eax, r14d                     ; ^ b
    xor eax, r15d                     ; ^ c
    mov byte [rdi + r12*4 + 3], al

    inc r12d
    cmp r12d, 4
    jb .mc_col

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; static void _inv_mix_columns(void *state)
_inv_mix_columns:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    xor r12d, r12d

.imc_col:
    movzx r13d, byte [rdi + r12*4]      ; a
    movzx r14d, byte [rdi + r12*4 + 1]  ; b
    movzx r15d, byte [rdi + r12*4 + 2]  ; c
    movzx ebx,  byte [rdi + r12*4 + 3]  ; d

    ; out_a = (0e * a) ^ (0b * b) ^ (0d * c) ^ (09 * d)
    mov eax, r13d
    call _xtime
    mov ecx, eax                       ; 2a
    mov eax, r13d
    call _xtime
    call _xtime                        ; 4a
    xor ecx, eax
    mov eax, r13d
    call _xtime                        ; 2a
    call _xtime                        ; 4a
    call _xtime                        ; 8a
    xor ecx, eax                       ; ecx = 0e * a

    mov eax, r14d
    call _xtime                        ; 2b
    mov edx, eax
    xor edx, r14d                      ; 3b
    mov eax, r14d
    call _xtime
    call _xtime
    call _xtime                        ; 8b
    xor edx, eax
    xor ecx, edx                       ; ^ 0b * b

    mov eax, r15d
    call _xtime
    call _xtime                        ; 4c
    mov edx, eax
    xor edx, r15d                      ; 4c ^ c
    mov eax, r15d
    call _xtime
    call _xtime
    call _xtime                        ; 8c
    xor edx, eax
    xor ecx, edx                       ; ^ 0d * c

    mov eax, ebx
    call _xtime
    call _xtime
    call _xtime                        ; 8d
    xor eax, ebx
    xor ecx, eax                       ; ^ 09 * d
    mov byte [rdi + r12*4], cl

    ; out_b = (09 * a) ^ (0e * b) ^ (0b * c) ^ (0d * d)
    mov eax, r13d
    call _xtime
    call _xtime
    call _xtime                        ; 8a
    xor eax, r13d
    mov ecx, eax                       ; ecx = 09 * a

    mov eax, r14d
    call _xtime
    mov edx, eax
    mov eax, r14d
    call _xtime
    call _xtime                        ; 4b
    xor edx, eax
    mov eax, r14d
    call _xtime                        ; 2b
    call _xtime                        ; 4b
    call _xtime                        ; 8b
    xor edx, eax
    xor ecx, edx                       ; ^ 0e * b

    mov eax, r15d
    call _xtime                        ; 2c
    mov edx, eax
    xor edx, r15d                      ; 3c
    mov eax, r15d
    call _xtime
    call _xtime
    call _xtime                        ; 8c
    xor edx, eax
    xor ecx, edx                       ; ^ 0b * c

    mov eax, ebx
    call _xtime
    call _xtime                        ; 4d
    mov edx, eax
    xor edx, ebx                       ; 4d ^ d
    mov eax, ebx
    call _xtime
    call _xtime
    call _xtime                        ; 8d
    xor edx, eax
    xor ecx, edx                       ; ^ 0d * d
    mov byte [rdi + r12*4 + 1], cl

    ; out_c = (0d * a) ^ (09 * b) ^ (0e * c) ^ (0b * d)
    mov eax, r13d
    call _xtime
    call _xtime                        ; 4a
    mov edx, eax
    xor edx, r13d
    mov eax, r13d
    call _xtime
    call _xtime
    call _xtime                        ; 8a
    xor edx, eax
    mov ecx, edx                       ; ecx = 0d * a

    mov eax, r14d
    call _xtime
    call _xtime
    call _xtime                        ; 8b
    xor eax, r14d
    xor ecx, eax                       ; ^ 09 * b

    mov eax, r15d
    call _xtime                        ; 2c
    mov edx, eax
    mov eax, r15d
    call _xtime
    call _xtime                        ; 4c
    xor edx, eax
    mov eax, r15d
    call _xtime                        ; 2c
    call _xtime                        ; 4c
    call _xtime                        ; 8c
    xor edx, eax
    xor ecx, edx                       ; ^ 0e * c

    mov eax, ebx
    call _xtime                        ; 2d
    mov edx, eax
    xor edx, ebx                       ; 3d
    mov eax, ebx
    call _xtime
    call _xtime
    call _xtime                        ; 8d
    xor edx, eax
    xor ecx, edx                       ; ^ 0b * d
    mov byte [rdi + r12*4 + 2], cl

    ; out_d = (0b * a) ^ (0d * b) ^ (09 * c) ^ (0e * d)
    mov eax, r13d
    call _xtime                        ; 2a
    mov edx, eax
    xor edx, r13d
    mov eax, r13d
    call _xtime
    call _xtime
    call _xtime                        ; 8a
    xor edx, eax
    mov ecx, edx                       ; ecx = 0b * a

    mov eax, r14d
    call _xtime
    call _xtime                        ; 4b
    mov edx, eax
    xor edx, r14d
    mov eax, r14d
    call _xtime
    call _xtime
    call _xtime                        ; 8b
    xor edx, eax
    xor ecx, edx                       ; ^ 0d * b

    mov eax, r15d
    call _xtime
    call _xtime
    call _xtime                        ; 8c
    xor eax, r15d
    xor ecx, eax                       ; ^ 09 * c

    mov eax, ebx
    call _xtime                        ; 2d
    mov edx, eax
    mov eax, ebx
    call _xtime
    call _xtime                        ; 4d
    xor edx, eax
    mov eax, ebx
    call _xtime                        ; 2d
    call _xtime                        ; 4d
    call _xtime                        ; 8d
    xor edx, eax
    xor ecx, edx                       ; ^ 0e * d
    mov byte [rdi + r12*4 + 3], cl

    inc r12d
    cmp r12d, 4
    jb .imc_col

    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; static void _add_round_key(void *state, const void *round_key)
; rdi = state, rsi = round_key (4 words)
_add_round_key:
    mov eax, [rsi]
    xor [rdi], eax
    mov eax, [rsi + 4]
    xor [rdi + 4], eax
    mov eax, [rsi + 8]
    xor [rdi + 8], eax
    mov eax, [rsi + 12]
    xor [rdi + 12], eax
    ret
; void aes128_encrypt_block(const void *block, const void *round_keys, void *output)
; rdi = block (16 bytes), rsi = round_keys (176 bytes), rdx = output
aes128_encrypt_block:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 16

    mov r12, rsi                         ; save round_keys base
    mov r14, rdx                         ; save output pointer

    ; Copy block to stack for working state
    mov rax, [rdi]
    mov [rsp], rax
    mov rax, [rdi + 8]
    mov [rsp + 8], rax

    ; Initial AddRoundKey (round 0)
    mov rdi, rsp
    mov rsi, r12
    call _add_round_key

    ; Rounds 1-9
    mov r13d, 1
.eb_loop:
    cmp r13d, 10
    jae .eb_final

    mov rdi, rsp
    call _sub_bytes
    mov rdi, rsp
    call _shift_rows
    mov rdi, rsp
    call _mix_columns
    mov rdi, rsp
    mov esi, r13d
    shl esi, 4
    add rsi, r12
    call _add_round_key

    inc r13d
    jmp .eb_loop

.eb_final:
    ; Round 10: SubBytes, ShiftRows, AddRoundKey (no MixColumns)
    mov rdi, rsp
    call _sub_bytes
    mov rdi, rsp
    call _shift_rows
    mov rdi, rsp
    lea rsi, [r12 + 10*16]
    call _add_round_key

    ; Copy state to output (r14 = output pointer)
    mov rax, [rsp]
    mov [r14], rax
    mov rax, [rsp + 8]
    mov [r14 + 8], rax

    add rsp, 16
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; void aes128_decrypt_block(const void *block, const void *round_keys, void *output)
; rdi = block, rsi = round_keys, rdx = output
aes128_decrypt_block:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 16

    mov r12, rsi                         ; save base round_keys
    mov r14, rdx                         ; save output pointer

    ; Copy block to stack
    mov rax, [rdi]
    mov [rsp], rax
    mov rax, [rdi + 8]
    mov [rsp + 8], rax

    ; Initial AddRoundKey with round 10 key
    mov rdi, rsp
    lea rsi, [r12 + 10*16]
    call _add_round_key

    ; Rounds 9 down to 1
    mov r13d, 9
.db_loop:
    mov rdi, rsp
    call _inv_shift_rows
    mov rdi, rsp
    call _inv_sub_bytes
    mov rdi, rsp
    mov esi, r13d
    shl esi, 4
    add rsi, r12
    call _add_round_key
    mov rdi, rsp
    call _inv_mix_columns

    dec r13d
    jnz .db_loop

    ; Final round: InvShiftRows, InvSubBytes, AddRoundKey (round 0)
    mov rdi, rsp
    call _inv_shift_rows
    mov rdi, rsp
    call _inv_sub_bytes
    mov rdi, rsp
    mov rsi, r12
    call _add_round_key

    ; Copy output
    mov rax, [rsp]
    mov [r14], rax
    mov rax, [rsp + 8]
    mov [r14 + 8], rax

    add rsp, 16
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; void aes128_cbc_encrypt(const void *key, const void *iv,
;                          const void *plaintext, uint64_t len,
;                          void *ciphertext)
; rdi=key, rsi=iv, rdx=plaintext, rcx=len, r8=ciphertext
; len must be multiple of 16
aes128_cbc_encrypt:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 208                         ; 176 for round_keys + 16 for iv_copy + 16 for block

    mov r12, rdi                         ; key
    mov r13, rsi                         ; iv
    mov r14, rdx                         ; plaintext
    mov r15, rcx                         ; len
    mov rbp, r8                          ; ciphertext output

    ; Expand key
    lea rsi, [rsp + 32]
    call aes128_key_expand               ; rdi=key, rsi=round_keys on stack

    ; Copy IV to stack
    lea rdi, [rsp]                       ; iv_copy at rsp
    mov rsi, r13                         ; source iv
    mov rcx, 16
    cld
    rep movsb

    ; Encrypt each block
    xor r13d, r13d                       ; block index

.ce_block:
    cmp r13, r15
    jae .ce_done

    ; XOR plaintext with IV (or previous ciphertext)
    add r14, r13                         ; current plaintext ptr
    lea rdi, [rsp + 16]                  ; block buffer
    lea rsi, [rsp]                       ; iv
    mov rcx, 16
    cld
    rep movsb                            ; block = iv

    sub r14, r13                         ; restore plaintext
    lea rsi, [r14 + r13]                 ; current plaintext ptr
    xor ecx, ecx
.ce_xor:
    movzx eax, byte [rsi + rcx]
    xor byte [rsp + 16 + rcx], al
    inc ecx
    cmp ecx, 16
    jb .ce_xor

    ; Encrypt block
    lea rdi, [rsp + 16]                  ; input block
    lea rsi, [rsp + 32]                  ; round_keys
    mov rdx, rdi                         ; output in-place
    call aes128_encrypt_block

    ; Copy ciphertext block to output and use as next IV
    add rbp, r13                         ; current ciphertext ptr
    lea rsi, [rsp + 16]                  ; encrypted block
    mov rdi, rbp
    mov rcx, 16
    cld
    rep movsb                            ; copy to output

    ; Copy encrypted block to IV for next round
    lea rsi, [rbp]                       ; just wrote ciphertext here
    lea rdi, [rsp]                       ; iv
    mov rcx, 16
    cld
    rep movsb

    sub rbp, r13                         ; restore ciphertext base
    add r13, 16
    jmp .ce_block

.ce_done:
    add rsp, 208
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; void aes128_cbc_decrypt(const void *key, const void *iv,
;                          const void *ciphertext, uint64_t len,
;                          void *plaintext)
; rdi=key, rsi=iv, rdx=ciphertext, rcx=len, r8=plaintext
aes128_cbc_decrypt:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 224                         ; 176 round_keys + 16 iv + 16 block + 16 prev_block

    mov r12, rdi                         ; key
    mov r13, rsi                         ; iv
    mov r14, rdx                         ; ciphertext
    mov r15, rcx                         ; len
    mov rbp, r8                          ; plaintext output

    ; Expand key (for decryption we use the same round_keys, just in reverse order)
    lea rsi, [rsp + 48]
    call aes128_key_expand

    ; Copy IV to stack
    lea rdi, [rsp + 32]
    mov rsi, r13
    mov rcx, 16
    cld
    rep movsb

    lea r13, [rsp + 32]                  ; r13 = iv pointer (updated each block: prev ciphertext)

    xor r12d, r12d                       ; block offset

.cd_block:
    cmp r12, r15
    jae .cd_done

    ; Copy ciphertext block to prev_block buffer (for next IV)
    lea rdi, [rsp + 16]
    mov rsi, r14
    add rsi, r12
    mov rcx, 16
    cld
    rep movsb                            ; save current ciphertext block

    ; Decrypt ciphertext block
    mov rdi, r14
    add rdi, r12                         ; ciphertext block
    lea rsi, [rsp + 48]                  ; round_keys
    lea rdx, [rsp]                       ; decrypted output buffer
    call aes128_decrypt_block

    ; XOR with IV
    xor ecx, ecx
.cd_xor:
    movzx eax, byte [rsp + rcx]
    movzx ebx, byte [r13 + rcx]         ; iv (or prev ciphertext)
    xor eax, ebx
    mov [rsp + rcx], al
    inc ecx
    cmp ecx, 16
    jb .cd_xor

    ; Copy decrypted block to output
    mov rdi, rbp
    add rdi, r12
    lea rsi, [rsp]
    mov rcx, 16
    cld
    rep movsb

    ; Use saved ciphertext as next IV
    lea r13, [rsp + 16]                  ; point iv at saved ciphertext

    add r12, 16
    jmp .cd_block

.cd_done:
    add rsp, 224
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
