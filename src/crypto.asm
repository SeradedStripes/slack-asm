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
