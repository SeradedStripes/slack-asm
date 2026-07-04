BITS 64
default rel

global run_gcm_tests

extern gcm_ghash_init, gcm_ghash_feed, gcm_ghash_final

section .rodata
; Test 1: H=0, data=0 -> expected 0
h1:    times 16 db 0
data1: times 16 db 0
exp1:  times 16 db 0

; Test 2: H=66e9...2b2e, data=0388...fe78 || 0000...80
h2:
    db 0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b
    db 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e
data2:
    db 0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92
    db 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
data2b:
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
exp2:
    db 0xf3, 0x8c, 0xbb, 0x1a, 0xd6, 0x92, 0x23, 0xdc
    db 0xc3, 0x45, 0x7a, 0xe5, 0xb6, 0xb0, 0xf8, 0x85

; Test 3: H=66e9...2b2e, data=0000...01
data3:
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
exp3:
    db 0x52, 0xa4, 0xdc, 0xb8, 0x14, 0xe5, 0x4a, 0xe1
    db 0xb2, 0xd2, 0x40, 0x2f, 0xdc, 0x6e, 0xb8, 0x49

; Test 4: Two-block: H=66e9...2b2e, data=data4a||data4b||data4c
data4a:
    db 0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92
    db 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
data4b:
    db 0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92
    db 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
data4c:
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
exp4:
    db 0x38, 0x82, 0x73, 0xd2, 0xee, 0x25, 0xe1, 0xfb
    db 0xab, 0xfa, 0xb3, 0xfc, 0x13, 0xb6, 0x8b, 0x22

section .bss
ctx:  resb 32
out:  resb 16
buf:  resb 64

section .text
run_gcm_tests:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16

    ; Test 1: H=0, data=0
    lea rdi, [ctx]
    lea rsi, [h1]
    call gcm_ghash_init
    lea rdi, [ctx]
    lea rsi, [data1]
    mov rdx, 16
    call gcm_ghash_feed
    lea rdi, [out]
    lea rsi, [ctx]
    call gcm_ghash_final
    lea rsi, [out]
    lea rdi, [exp1]
    mov ecx, 16
    cld
    repe cmpsb
    jnz .fail

    ; Test 2: H=66e9..., data=0388...fe78 || 0000...80
    lea rdi, [buf]
    lea rsi, [data2]
    mov ecx, 16
    cld
    rep movsb
    lea rsi, [data2b]
    mov ecx, 16
    rep movsb

    lea rdi, [ctx]
    lea rsi, [h2]
    call gcm_ghash_init
    lea rdi, [ctx]
    lea rsi, [buf]
    mov rdx, 32
    call gcm_ghash_feed
    lea rdi, [out]
    lea rsi, [ctx]
    call gcm_ghash_final
    lea rsi, [out]
    lea rdi, [exp2]
    mov ecx, 16
    cld
    repe cmpsb
    jnz .fail

    ; Test 3: H=66e9..., data=0000...01
    lea rdi, [ctx]
    lea rsi, [h2]
    call gcm_ghash_init
    lea rdi, [ctx]
    lea rsi, [data3]
    mov rdx, 16
    call gcm_ghash_feed
    lea rdi, [out]
    lea rsi, [ctx]
    call gcm_ghash_final
    lea rsi, [out]
    lea rdi, [exp3]
    mov ecx, 16
    cld
    repe cmpsb
    jnz .fail

    ; Test 4: Two-block
    lea rdi, [buf]
    lea rsi, [data4a]
    mov ecx, 16
    cld
    rep movsb
    lea rsi, [data4b]
    mov ecx, 16
    rep movsb
    lea rsi, [data4c]
    mov ecx, 16
    rep movsb

    lea rdi, [ctx]
    lea rsi, [h2]
    call gcm_ghash_init
    lea rdi, [ctx]
    lea rsi, [buf]
    mov rdx, 48
    call gcm_ghash_feed
    lea rdi, [out]
    lea rsi, [ctx]
    call gcm_ghash_final
    lea rsi, [out]
    lea rdi, [exp4]
    mov ecx, 16
    cld
    repe cmpsb
    jnz .fail

    xor eax, eax
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.fail:
    mov eax, 1
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
