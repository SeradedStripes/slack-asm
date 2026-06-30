BITS 64
default rel

%define SYS_write  1
%define SYS_exit   60
%define STDOUT     1

extern gcm_ghash_init
extern gcm_ghash_feed
extern gcm_ghash_final

section .rodata

; Test 1: H=0, data=0 -> expected 0
h1:    times 16 db 0
data1: times 16 db 0
exp1:  times 16 db 0

; Test 2: H=66e9...2b2e, data=0388...fe78 -> expected f38c...885
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

; Test 3: H=66e9...2b2e, data=0000...01 -> expected 52a4...49
data3:
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
exp3:
    db 0x52, 0xa4, 0xdc, 0xb8, 0x14, 0xe5, 0x4a, 0xe1
    db 0xb2, 0xd2, 0x40, 0x2f, 0xdc, 0x6e, 0xb8, 0x49

; Two-block test: H=66e9...2b2e, data=(0388...fe78)*2 + len block -> 3882...b22
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

msg_pass: db "PASS", 10
msg_pass_len: equ $ - msg_pass
msg_fail: db "FAIL", 10
msg_fail_len: equ $ - msg_fail
msg_test: db "Test ", 0
msg_colon: db ": ", 0

section .bss
ctx:  resb 32
out:  resb 16
buf:  resb 64

section .text
global _start
_start:
    xor ebp, ebp
    call main
    mov edi, eax
    mov eax, SYS_exit
    syscall

; Print a null-terminated string at rsi
print_str:
    push rax
    push rdi
    push rsi
    push rdx
    xor rdx, rdx
.ps_loop:
    cmp byte [rsi + rdx], 0
    je .ps_done
    inc rdx
    jmp .ps_loop
.ps_done:
    mov eax, SYS_write
    mov edi, STDOUT
    syscall
    pop rdx
    pop rsi
    pop rdi
    pop rax
    ret

; Print a 1-digit decimal number (0-9) in dil
print_digit:
    push rax
    push rdi
    push rsi
    push rdx
    mov byte [buf], '0'
    add [buf], dil
    mov eax, SYS_write
    mov edi, STDOUT
    lea rsi, [buf]
    mov edx, 1
    syscall
    pop rdx
    pop rsi
    pop rdi
    pop rax
    ret

print_msg_pass:
    mov eax, SYS_write
    mov edi, STDOUT
    lea rsi, [msg_pass]
    mov edx, msg_pass_len
    syscall
    ret

print_msg_fail:
    mov eax, SYS_write
    mov edi, STDOUT
    lea rsi, [msg_fail]
    mov edx, msg_fail_len
    syscall
    ret

; Run one GHASH test
; rdi = H pointer, rsi = data pointer, rdx = data length, rcx = expected
; Returns 0 in eax on success, 1 on failure
run_test:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16

    mov r12, rdi            ; H
    mov r13, rsi            ; data
    mov r14, rdx            ; len
    mov r15, rcx            ; expected

    ; gcm_ghash_init(ctx, H)
    lea rdi, [ctx]
    mov rsi, r12
    call gcm_ghash_init

    ; gcm_ghash_feed(ctx, data, len)
    lea rdi, [ctx]
    mov rsi, r13
    mov rdx, r14
    call gcm_ghash_feed

    ; gcm_ghash_final(out, ctx)
    lea rdi, [out]
    lea rsi, [ctx]
    call gcm_ghash_final

    ; Compare out with expected
    lea rsi, [out]
    mov rdi, r15
    mov ecx, 16
    cld
    repe cmpsb
    jz .test_pass

    mov eax, 1
    jmp .test_done

.test_pass:
    xor eax, eax

.test_done:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

main:
    push rbx

    xor ebx, ebx   ; test counter

    ; Test 1: H=0, data=0
    inc ebx
    mov dil, bl
    call print_digit
    lea rsi, [msg_colon]
    call print_str
    lea rdi, [h1]
    lea rsi, [data1]
    mov rdx, 16
    lea rcx, [exp1]
    call run_test
    test eax, eax
    jnz .fail

    call print_msg_pass

    ; Test 2: H=66e9..., data=(0388...fe78 || 0000...80)
    inc ebx
    mov dil, bl
    call print_digit
    lea rsi, [msg_colon]
    call print_str
    lea rdi, [h2]

    ; Build data = data2 || data2b
    lea rdi, [buf]
    lea rsi, [data2]
    mov ecx, 16
    cld
    rep movsb
    lea rsi, [data2b]
    mov ecx, 16
    rep movsb

    lea rdi, [h2]
    lea rsi, [buf]
    mov rdx, 32
    lea rcx, [exp2]
    call run_test
    test eax, eax
    jnz .fail

    call print_msg_pass

    ; Test 3: H=66e9..., data=0000...01
    inc ebx
    mov dil, bl
    call print_digit
    lea rsi, [msg_colon]
    call print_str
    lea rdi, [h2]
    lea rsi, [data3]
    mov rdx, 16
    lea rcx, [exp3]
    call run_test
    test eax, eax
    jnz .fail

    call print_msg_pass

    ; Test 4: Two-block (data4a || data4b || data4c)
    inc ebx
    mov dil, bl
    call print_digit
    lea rsi, [msg_colon]
    call print_str
    lea rdi, [h2]

    ; Build data = data4a || data4b || data4c
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

    lea rdi, [h2]
    lea rsi, [buf]
    mov rdx, 48
    lea rcx, [exp4]
    call run_test
    test eax, eax
    jnz .fail

    call print_msg_pass

    xor eax, eax
    pop rbx
    ret

.fail:
    call print_msg_fail
    mov eax, 1
    pop rbx
    ret
