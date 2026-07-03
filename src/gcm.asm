; AES-128-GCM for TLS 1.2 (RFC 5288, NIST SP 800-38D)

BITS 64
default rel

extern aes128_key_expand
extern aes128_encrypt_block

section .text
global gcm_ghash_init
global gcm_ghash_feed
global gcm_ghash_final
global gcm_ghash
global aes128_gcm_encrypt
global aes128_gcm_decrypt

; GF(2^128) multiply: Y = Y * H  (in-place)
; rdi = Y (16 bytes in/out), rsi = H (16 bytes, read-only)
_gf128_mul:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48

    mov r12, rdi
    mov r13, rsi

    ; V = H at rsp+0
    mov rax, [r13]
    mov [rsp], rax
    mov rax, [r13 + 8]
    mov [rsp + 8], rax

    ; X = Y at rsp+16
    mov rax, [r12]
    mov [rsp + 16], rax
    mov rax, [r12 + 8]
    mov [rsp + 24], rax

    ; Z = 0 at rsp+32
    xor eax, eax
    mov [rsp + 32], rax
    mov [rsp + 40], rax

    xor r14d, r14d
.gf_loop:
    mov ecx, r14d
    shr ecx, 3
    movzx eax, byte [rsp + 16 + rcx]
    mov ecx, r14d
    and ecx, 7
    xor ecx, 7
    bt eax, ecx
    jnc .gf_noxor

    ; Z ^= V
    mov rax, [rsp + 32]
    xor rax, [rsp]
    mov [rsp + 32], rax
    mov rax, [rsp + 40]
    xor rax, [rsp + 8]
    mov [rsp + 40], rax

.gf_noxor:
    test byte [rsp + 15], 1
    jz .gf_shift

    ; V = (V >> 1) ^ (0xE1 << 120)
    xor ebx, ebx
    xor ecx, ecx
.gf_sr_xor:
    movzx eax, byte [rsp + rcx]
    mov edx, eax
    shr al, 1
    and dl, 1
    shl dl, 7
    or al, bl
    mov [rsp + rcx], al
    mov ebx, edx
    inc ecx
    cmp ecx, 16
    jb .gf_sr_xor
    xor byte [rsp], 0xE1
    jmp .gf_next

.gf_shift:
    xor ebx, ebx
    xor ecx, ecx
.gf_sr:
    movzx eax, byte [rsp + rcx]
    mov edx, eax
    shr al, 1
    and dl, 1
    shl dl, 7
    or al, bl
    mov [rsp + rcx], al
    mov ebx, edx
    inc ecx
    cmp ecx, 16
    jb .gf_sr

.gf_next:
    inc r14d
    cmp r14d, 128
    jb .gf_loop

    ; Z -> Y
    mov rax, [rsp + 32]
    mov [r12], rax
    mov rax, [rsp + 40]
    mov [r12 + 8], rax

    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret


; gcm_ghash_init(void *ctx, const void *H)
; ctx[0..15] = H, ctx[16..31] = 0
gcm_ghash_init:
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi + 8]
    mov [rdi + 8], rax
    xor eax, eax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    ret


; gcm_ghash_feed(void *ctx, const void *data, size_t len)
; Processes len bytes; zero-pads the final partial block.
gcm_ghash_feed:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16

    mov r12, rdi               ; ctx
    mov r13, rsi               ; data
    mov r14, rdx               ; len

    xor r15d, r15d             ; offset
.gf_feed_loop:
    cmp r15d, r14d
    jae .gf_feed_done

    mov ecx, r14d
    sub ecx, r15d
    cmp ecx, 16
    jb .gf_partial_block

    ; Full block: Y ^= block
    mov rax, [r12 + 16]
    xor rax, [r13 + r15]
    mov [r12 + 16], rax
    mov rax, [r12 + 24]
    xor rax, [r13 + r15 + 8]
    mov [r12 + 24], rax

    ; Y = Y * H
    lea rdi, [r12 + 16]
    mov rsi, r12
    call _gf128_mul

    add r15d, 16
    jmp .gf_feed_loop

.gf_partial_block:
    ; Copy partial to scratch on stack
    ; rsp[0..15] is our scratch area
    lea rdi, [rsp]
    mov rsi, r13
    add rsi, r15
    push rcx                   ; save byte count
    rep movsb
    pop rcx
    ; Zero-pad (rcx is count, remaining = 16 - rcx)
    neg ecx
    add ecx, 16
    xor eax, eax
    rep stosb

    ; Y ^= padded block
    mov rax, [r12 + 16]
    xor rax, [rsp]
    mov [r12 + 16], rax
    mov rax, [r12 + 24]
    xor rax, [rsp + 8]
    mov [r12 + 24], rax

    ; Y = Y * H
    lea rdi, [r12 + 16]
    mov rsi, r12
    call _gf128_mul

.gf_feed_done:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; gcm_ghash_final(void *out, const void *ctx)
gcm_ghash_final:
    mov rax, [rsi + 16]
    mov [rdi], rax
    mov rax, [rsi + 24]
    mov [rdi + 8], rax
    ret


; gcm_ghash(void *out, const void *H, const void *data, size_t len)
; Convenience wrapper (single-call GHASH)
gcm_ghash:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32

    mov r12, rdi               ; out
    mov r13, rsi               ; H
    mov r14, rdx               ; data
    mov r15, rcx               ; len

    ; Init ctx at rsp
    mov rdi, rsp
    mov rsi, r13
    call gcm_ghash_init

    ; Feed
    mov rdi, rsp
    mov rsi, r14
    mov rdx, r15
    call gcm_ghash_feed

    ; Final
    mov rdi, r12
    mov rsi, rsp
    call gcm_ghash_final

    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; Increment last 32 bits of counter block (big-endian)
_gcm_inc32:
    mov eax, [rdi + 12]
    bswap eax
    inc eax
    bswap eax
    mov [rdi + 12], eax
    ret


; aes128_gcm_encrypt
; rdi=key(16), rsi=nonce(12), rdx=pt, rcx=pt_len,
; r8=aad, r9=aad_len, [rsp+0]=ct_out, [rsp+8]=tag_out(16)
; Returns 0 on success
aes128_gcm_encrypt:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 288

    mov r12, rdi               ; key
    mov r13, rsi               ; nonce
    mov r14, rdx               ; plaintext
    mov r15, rcx               ; pt_len
    mov rbp, [rsp + 344]       ; ct_out
    mov rbx, [rsp + 352]       ; tag_out

    ; Expand key -> rsp+0
    mov rdi, r12
    lea rsi, [rsp]
    call aes128_key_expand

    ; H = AES(K, 0) at rsp+176
    xor eax, eax
    mov [rsp + 256], rax
    mov [rsp + 264], rax
    lea rdi, [rsp + 256]
    lea rsi, [rsp]
    lea rdx, [rsp + 176]
    call aes128_encrypt_block

    ; J0 = nonce || 0x00000001 at rsp+192
    lea rdi, [rsp + 192]
    mov rsi, r13
    movsq
    movsd
    mov dword [rsp + 204], 0x01000000

    ; AES(J0) for tag masking at rsp+208
    lea rdi, [rsp + 192]
    lea rsi, [rsp]
    lea rdx, [rsp + 208]
    call aes128_encrypt_block

    ; Counter = J0 + 1 at rsp+224
    mov rax, [rsp + 192]
    mov [rsp + 224], rax
    mov rax, [rsp + 200]
    mov [rsp + 232], rax
    lea rdi, [rsp + 224]
    call _gcm_inc32

    ; Encrypt plaintext
    xor r10d, r10d             ; offset
.ge_ctr:
    cmp r10d, r15d
    jae .ge_ctr_done

    mov eax, r15d
    sub eax, r10d
    cmp eax, 16
    jb .ge_partial

    lea rdi, [rsp + 224]
    lea rsi, [rsp]
    lea rdx, [rsp + 240]
    call aes128_encrypt_block
    lea rdi, [rsp + 224]
    call _gcm_inc32

    mov rax, [r14 + r10]
    xor rax, [rsp + 240]
    mov [rbp + r10], rax
    mov rax, [r14 + r10 + 8]
    xor rax, [rsp + 248]
    mov [rbp + r10 + 8], rax

    add r10d, 16
    jmp .ge_ctr

.ge_partial:
    mov [rsp + 192], eax         ; save remaining byte count (J0 is dead)

    lea rdi, [rsp + 224]
    lea rsi, [rsp]
    lea rdx, [rsp + 240]
    call aes128_encrypt_block



    mov eax, [rsp + 192]         ; restore remaining byte count
    xor r11d, r11d
.ge_part_loop:
    test eax, eax
    jz .ge_ctr_done
    mov cl, [r14 + r10]
    xor cl, [rsp + 240 + r11]
    mov [rbp + r10], cl
    inc r10
    inc r11d
    dec eax
    jnz .ge_part_loop

.ge_ctr_done:
    ; GHASH tag computation
    ; ctx at rsp+256
    lea rdi, [rsp + 256]
    lea rsi, [rsp + 176]
    call gcm_ghash_init

    ; Feed AAD
    lea rdi, [rsp + 256]
    mov rsi, r8
    mov rdx, r9
    call gcm_ghash_feed

    ; Feed ciphertext
    lea rdi, [rsp + 256]
    mov rsi, rbp
    mov rdx, r15
    call gcm_ghash_feed

    ; Length block (stored at non-overlapping scratch rsp+160)
    mov eax, r9d
    shl rax, 3
    bswap rax
    mov [rsp + 160], rax
    mov eax, r15d
    shl rax, 3
    bswap rax
    mov [rsp + 168], rax

    lea rdi, [rsp + 256]
    lea rsi, [rsp + 160]
    mov rdx, 16
    call gcm_ghash_feed

    ; Final GHASH result into ctx+16 (already points to Y, so
    ; ghash_final copies ctx Y to itself — a no-op in place)
    lea rdi, [rsp + 272]
    lea rsi, [rsp + 256]
    call gcm_ghash_final

    ; Tag = GHASH_result XOR AES(J0)
    mov rax, [rsp + 272]
    xor rax, [rsp + 208]
    mov [rbx], rax
    mov rax, [rsp + 280]
    xor rax, [rsp + 216]
    mov [rbx + 8], rax

    xor eax, eax
    add rsp, 288
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret


; aes128_gcm_decrypt
; rdi=key(16), rsi=nonce(12), rdx=ct, rcx=ct_len,
; r8=aad, r9=aad_len, [rsp+0]=tag(16), [rsp+8]=pt_out
; Returns 0 on success, -1 on tag mismatch
aes128_gcm_decrypt:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 320

    mov r12, rdi               ; key
    mov r13, rsi               ; nonce
    mov r14, rdx               ; ciphertext
    mov r15, rcx               ; ct_len
    mov rbp, [rsp + 376]       ; tag
    mov rbx, [rsp + 384]       ; plaintext_out

    ; Expand key
    mov rdi, r12
    lea rsi, [rsp]
    call aes128_key_expand

    ; H = AES(K, 0)
    xor eax, eax
    mov [rsp + 256], rax
    mov [rsp + 264], rax
    lea rdi, [rsp + 256]
    lea rsi, [rsp]
    lea rdx, [rsp + 176]
    call aes128_encrypt_block

    ; J0 = nonce || 0x00000001
    lea rdi, [rsp + 192]
    mov rsi, r13
    movsq
    movsd
    mov dword [rsp + 204], 0x01000000

    ; AES(J0) for tag verification
    lea rdi, [rsp + 192]
    lea rsi, [rsp]
    lea rdx, [rsp + 208]
    call aes128_encrypt_block

    ; Counter = J0 + 1
    mov rax, [rsp + 192]
    mov [rsp + 224], rax
    mov rax, [rsp + 200]
    mov [rsp + 232], rax
    lea rdi, [rsp + 224]
    call _gcm_inc32

    ; Decrypt ciphertext
    xor r10d, r10d
.gd_ctr:
    cmp r10d, r15d
    jae .gd_ctr_done

    mov eax, r15d
    sub eax, r10d
    cmp eax, 16
    jb .gd_partial

    lea rdi, [rsp + 224]
    lea rsi, [rsp]
    lea rdx, [rsp + 240]
    call aes128_encrypt_block
    lea rdi, [rsp + 224]
    call _gcm_inc32

    mov rax, [r14 + r10]
    xor rax, [rsp + 240]
    mov [rbx + r10], rax
    mov rax, [r14 + r10 + 8]
    xor rax, [rsp + 248]
    mov [rbx + r10 + 8], rax

    add r10d, 16
    jmp .gd_ctr

.gd_partial:
    lea rdi, [rsp + 224]
    lea rsi, [rsp]
    lea rdx, [rsp + 240]
    call aes128_encrypt_block

    mov eax, r15d
    sub eax, r10d
    xor r11d, r11d
.gd_part_loop:
    test eax, eax
    jz .gd_ctr_done
    mov cl, [r14 + r10]
    xor cl, [rsp + 240 + r11]
    mov [rbx + r10], cl
    inc r10
    inc r11d
    dec eax
    jnz .gd_part_loop

.gd_ctr_done:
    ; Compute expected tag
    lea rdi, [rsp + 256]
    lea rsi, [rsp + 176]
    call gcm_ghash_init

    lea rdi, [rsp + 256]
    mov rsi, r8
    mov rdx, r9
    call gcm_ghash_feed

    lea rdi, [rsp + 256]
    mov rsi, r14               ; ciphertext
    mov rdx, r15
    call gcm_ghash_feed

    ; Length block (stored at non-overlapping scratch rsp+160)
    mov eax, r9d
    shl rax, 3
    bswap rax
    mov [rsp + 160], rax
    mov eax, r15d
    shl rax, 3
    bswap rax
    mov [rsp + 168], rax

    lea rdi, [rsp + 256]
    lea rsi, [rsp + 160]
    mov rdx, 16
    call gcm_ghash_feed

    lea rdi, [rsp + 272]
    lea rsi, [rsp + 256]
    call gcm_ghash_final

    ; Tag = GHASH ^ AES(J0)
    mov rax, [rsp + 272]
    xor rax, [rsp + 208]
    mov [rsp + 272], rax
    mov rax, [rsp + 280]
    xor rax, [rsp + 216]
    mov [rsp + 280], rax

    ; Compare with provided tag
    mov rsi, rbp               ; provided tag
    lea rdi, [rsp + 272]       ; computed tag

    ; Use 4 dword compares for constant-time-ish comparison
    xor eax, eax
    mov ecx, [rsi]
    xor ecx, [rdi]
    or eax, ecx
    mov ecx, [rsi + 4]
    xor ecx, [rdi + 4]
    or eax, ecx
    mov ecx, [rsi + 8]
    xor ecx, [rdi + 8]
    or eax, ecx
    mov ecx, [rsi + 12]
    xor ecx, [rdi + 12]
    or eax, ecx

    neg eax
    sbb eax, eax

    add rsp, 320
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
