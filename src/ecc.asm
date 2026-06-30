; P-256 (secp256r1) elliptic curve primitives for ECDHE key exchange

BITS 64
default rel

%define LIMBS 4

; External bignum functions from rsa.asm
extern big_mul
extern big_mod
extern big_mod_pow
extern big_cmp

section .rodata

; P-256 prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1
; Little-endian 64-bit limbs
; limb[0] = bits 0..63, limb[3] = bits 192..255
p256_p:  dq 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF
         dq 0x0000000000000000, 0xFFFFFFFF00000001

; Order n (not used directly for ECDHE, but for key generation)
p256_n:  dq 0xF3B9CAC2FC632551, 0xBCE6FAADA7179E84
         dq 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000

; Curve coefficient b (a = -3 mod p, handled inline)
p256_b:  dq 0x3BCE3C3E27D2604B, 0x651D06B0CC53B0F6
         dq 0xB3EBBD55769886BC, 0x5AC635D8AA3A93E7

; Generator point G
p256_Gx: dq 0xF4A13945D898C296, 0x77037D812DEB33A0
         dq 0xF8BCE6E563A440F2, 0x6B17D1F2E12C4247
p256_Gy: dq 0xCBB6406837BF51F5, 0x2BCE33576B315ECE
         dq 0x8EE7EB4A7C0F9E16, 0x4FE342E2FE1A7F9B

; p - 2 for Fermat inversion (a^(p-2) mod p)
p256_pm2: dq 0xFFFFFFFFFFFFFFFD, 0x00000000FFFFFFFF
          dq 0x0000000000000000, 0xFFFFFFFF00000001

; 2 (for doubling formula)
p256_two: dq 2, 0, 0, 0

; 3 (for doubling formula)
p256_three: dq 3, 0, 0, 0

; a = p - 3 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
p256_a: dq 0xFFFFFFFFFFFFFFFC, 0x00000000FFFFFFFF
        dq 0x0000000000000000, 0xFFFFFFFF00000001

section .bss
; 8 scratch slots of 32 bytes each = 256 bytes
fe_tmp: resq 40

section .text
global fe_add
global fe_sub
global fe_mul
global fe_sqr
global fe_inv
global ecc_point_add
global ecc_point_double
global ecc_scalar_mult
global ecc_scalar_mult_base
global ecc_is_infinity

; Load a 4-limb field element from [rsi] into rax:rbx:rcx:rdx (r0:r1:r2:r3)
%macro fe_load 0
    mov rax, [rsi]
    mov rbx, [rsi + 8]
    mov rcx, [rsi + 16]
    mov rdx, [rsi + 24]
%endmacro

; Store 4-limb field element from rax:rbx:rcx:rdx into [rdi]
%macro fe_store 0
    mov [rdi], rax
    mov [rdi + 8], rbx
    mov [rdi + 16], rcx
    mov [rdi + 24], rdx
%endmacro

; Subtract p from rax:rbx:rcx:rdx (in-place, result in same regs)
; Uses r8, r9, r10, r11 as scratch
%macro fe_sub_p 0
    sub rax, [p256_p]
    sbb rbx, [p256_p + 8]
    sbb rcx, [p256_p + 16]
    sbb rdx, [p256_p + 24]
%endmacro

; Add p to rax:rbx:rcx:rdx (in-place)
%macro fe_add_p 0
    add rax, [p256_p]
    adc rbx, [p256_p + 8]
    adc rcx, [p256_p + 16]
    adc rdx, [p256_p + 24]
%endmacro


; r = (a + b) mod p
; rdi = r, rsi = a, rdx = b
fe_add:
    push rbx
    push r12
    push r14

    mov r14, rdx        ; save source2 pointer (fe_load clobbers rdx)
    fe_load
    mov r8, rax
    mov r9, rbx
    mov r10, rcx
    mov r11, rdx

    mov rax, r8
    mov rbx, r9
    mov rcx, r10
    mov rdx, r11
    add rax, [r14]
    adc rbx, [r14 + 8]
    adc rcx, [r14 + 16]
    adc rdx, [r14 + 24]
    mov r12, 0
    adc r12, 0

    ; If carry, subtract p once
    test r12, r12
    jnz .fa_subp

    ; Check if >= p
    cmp rdx, [p256_p + 24]
    jb .fa_store
    ja .fa_subp
    cmp rcx, [p256_p + 16]
    jb .fa_store
    ja .fa_subp
    cmp rbx, [p256_p + 8]
    jb .fa_store
    ja .fa_subp
    cmp rax, [p256_p]
    jb .fa_store

.fa_subp:
    fe_sub_p

.fa_store:
    fe_store

    pop r14
    pop r12
    pop rbx
    ret


; r = (a - b) mod p
; rdi = r, rsi = a, rdx = b
fe_sub:
    push rbx
    push r12
    push r14

    mov r14, rdx        ; save source2 pointer (fe_load clobbers rdx)
    fe_load
    sub rax, [r14]
    sbb rbx, [r14 + 8]
    sbb rcx, [r14 + 16]
    sbb rdx, [r14 + 24]
    mov r12, 0
    adc r12, 0

    test r12, r12
    jz .fs_store
    fe_add_p

.fs_store:
    fe_store

    pop r14
    pop r12
    pop rbx
    ret


; r = (a * b) mod p
; rdi = r, rsi = a, rdx = b
; Uses fe_tmp[32..39] as 8-limb product buffer
fe_mul:
    push r15
    push r14
    push r13
    push r12
    push rdi
    push rsi
    push rdx

    ; big_mul(&fe_tmp[32], a, b, 4) -> 8-limb product
    lea rdi, [rel fe_tmp + 32*8]
    pop rdx
    pop rsi
    push rsi
    push rdx
    mov ecx, LIMBS
    call big_mul

    ; big_mod(r, &fe_tmp[32], p, 4)
    pop rdx
    pop rsi
    pop rdi
    lea rsi, [rel fe_tmp + 32*8]
    lea rdx, [rel p256_p]
    mov ecx, LIMBS
    call big_mod

    pop r12
    pop r13
    pop r14
    pop r15
    ret


; r = a^2 mod p
; rdi = r, rsi = a
fe_sqr:
    push rsi
    push rdi
    mov rdx, rsi
    call fe_mul
    pop rdi
    pop rsi
    ret


; r = a^(-1) mod p (Fermat: a^(p-2) mod p)
; rdi = r, rsi = a
fe_inv:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9

    mov rdi, rdi
    mov rsi, rsi
    lea rdx, [rel p256_pm2]
    mov ecx, LIMBS
    lea r8, [rel p256_p]
    mov r9d, LIMBS
    call big_mod_pow

    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ret


; Check if point [rdi] (x only, 4 limbs) is zero (infinity marker)
ecc_is_infinity:
    mov rax, [rdi]
    or rax, [rdi + 8]
    or rax, [rdi + 16]
    or rax, [rdi + 24]
    test rax, rax
    setz al
    movzx eax, al
    ret

_ecc_point_add_internal:
    push r12
    push r13
    push r14
    push r15
    sub rsp, 96                  ; 3 local slots of 32 bytes

    mov r12, rdi                 ; result
    mov r13, rsi                 ; P
    mov r14, rdx                 ; Q

    ; Check for infinity
    mov rdi, r14
    call ecc_is_infinity
    test eax, eax
    jz .epai_check_p

    ; Q is infinity, return P
    mov rdi, r12
    mov rsi, r13
    call _cpy64
    jmp .epai_done

.epai_check_p:
    mov rdi, r13
    call ecc_is_infinity
    test eax, eax
    jz .epai_norm

    ; P is infinity, return Q
    mov rdi, r12
    mov rsi, r14
    call _cpy64
    jmp .epai_done

.epai_norm:
    ; Check if P == Q (same x)
    mov rdi, r13
    mov rsi, r14
    mov edx, 4
    call big_cmp
    test eax, eax
    jne .epai_add
    ; Same x - check y
    lea rdi, [r13 + 32]
    lea rsi, [r14 + 32]
    mov edx, 4
    call big_cmp
    test eax, eax
    jne .epai_inv
    ; Same point - double
    mov rdi, r12
    mov rsi, r13
    call ecc_point_double
    jmp .epai_done

.epai_inv:
    ; Negated point: P + (-P) = O
    ; Return zero (infinity)
    mov rdi, r12
    xor eax, eax
    mov [rdi], rax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    mov [rdi + 32], rax
    mov [rdi + 40], rax
    mov [rdi + 48], rax
    mov [rdi + 56], rax
    jmp .epai_done

.epai_add:
    ; General addition: lambda = (y2 - y1) / (x2 - x1)
    ; x3 = lambda^2 - x1 - x2
    ; y3 = lambda*(x1 - x3) - y1

    ; t0 = y2 - y1
    lea rdi, [rsp]               ; t0
    lea rsi, [r14 + 32]          ; y2
    mov rdx, r13
    add rdx, 32                  ; y1
    call fe_sub

    ; t1 = x2 - x1
    lea rdi, [rsp + 32]          ; t1
    mov rsi, r14                 ; x2
    mov rdx, r13                 ; x1
    call fe_sub

    ; lambda = t0 / t1
    ; First invert t1
    lea rdi, [rsp + 64]          ; t1_inv
    lea rsi, [rsp + 32]          ; t1
    call fe_inv

    ; lambda = t0 * t1_inv
    lea rdi, [rsp + 32]          ; lambda (reuse t1 slot)
    lea rsi, [rsp]               ; t0
    lea rdx, [rsp + 64]          ; t1_inv
    call fe_mul

    ; x3 = lambda^2 - x1 - x2
    lea rdi, [rsp]               ; x3 (reuse t0 slot)
    lea rsi, [rsp + 32]          ; lambda
    call fe_sqr
    mov rdi, rsp
    lea rsi, [rsp]               ; x3
    mov rdx, r13                 ; x1
    call fe_sub
    mov rdi, rsp
    lea rsi, [rsp]               ; x3
    mov rdx, r14                 ; x2
    call fe_sub

    ; y3 = lambda*(x1 - x3) - y1
    lea rdi, [rsp + 64]          ; y3
    mov rsi, r13                 ; x1
    mov rdx, rsp                 ; x3
    call fe_sub
    mov rdi, [rsp + 64]

    lea rdi, [rsp + 64]          ; reuse for result
    lea rsi, [rsp + 64]          ; (x1 - x3)
    lea rdx, [rsp + 32]          ; lambda
    call fe_mul
    ; Now subtract y1
    mov rdi, r12
    add rdi, 32
    lea rsi, [rsp + 64]
    mov rdx, r13
    add rdx, 32
    call fe_sub

    ; Copy x3 to result
    mov rdi, r12
    lea rsi, [rsp]
    call _cpy32

.epai_done:
    add rsp, 96
    pop r15
    pop r14
    pop r13
    pop r12
    ret


; Copy 32 bytes from [rsi] to [rdi]
_cpy32:
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi + 8]
    mov [rdi + 8], rax
    mov rax, [rsi + 16]
    mov [rdi + 16], rax
    mov rax, [rsi + 24]
    mov [rdi + 24], rax
    ret

; Copy 64 bytes (x+y) from [rsi] to [rdi]
_cpy64:
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi + 8]
    mov [rdi + 8], rax
    mov rax, [rsi + 16]
    mov [rdi + 16], rax
    mov rax, [rsi + 24]
    mov [rdi + 24], rax
    mov rax, [rsi + 32]
    mov [rdi + 32], rax
    mov rax, [rsi + 40]
    mov [rdi + 40], rax
    mov rax, [rsi + 48]
    mov [rdi + 48], rax
    mov rax, [rsi + 56]
    mov [rdi + 56], rax
    ret


; Affine point doubling: 2*P
; rdi = result (x,y), rsi = P (x,y)
ecc_point_double:
    push r12
    push r13
    push r14
    push r15
    sub rsp, 128                 ; 4 slots of 32 bytes

    mov r12, rdi                 ; result
    mov r13, rsi                 ; P

    ; Check infinity
    mov rdi, r13
    call ecc_is_infinity
    test eax, eax
    jz .epd_norm

    ; Infinity → return infinity
    mov rdi, r12
    xor eax, eax
    mov [rdi], rax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    mov [rdi + 32], rax
    mov [rdi + 40], rax
    mov [rdi + 48], rax
    mov [rdi + 56], rax
    jmp .epd_done

.epd_norm:
    ; lambda = (3*x1^2 + a) / (2*y1)
    ; x3 = lambda^2 - 2*x1
    ; y3 = lambda*(x1 - x3) - y1

    ; t0 = x1^2
    lea rdi, [rsp]               ; t0
    mov rsi, r13                 ; x1
    call fe_sqr

    ; t1 = 3 * t0 = 3*x1^2
    lea rdi, [rsp + 32]          ; t1
    lea rsi, [rsp]               ; t0
    lea rdx, [rel p256_three]
    call fe_mul

    ; t2 = t1 + a = 3*x1^2 + a
    lea rdi, [rsp + 64]          ; t2
    lea rsi, [rsp + 32]          ; t1
    lea rdx, [rel p256_a]
    call fe_add

    ; t3 = 2*y1
    lea rdi, [rsp + 96]          ; t3
    mov rsi, r13
    add rsi, 32                  ; y1
    lea rdx, [rel p256_two]
    call fe_mul

    ; t3_inv = 1 / (2*y1)
    lea rdi, [rsp]               ; reuse t0 slot for t3_inv
    lea rsi, [rsp + 96]          ; t3
    call fe_inv

    ; lambda = (3*x1^2 + a) * t3_inv
    lea rdi, [rsp + 32]          ; lambda (reuse t1 slot)
    lea rsi, [rsp + 64]          ; t2
    lea rdx, [rsp]               ; t3_inv
    call fe_mul

    ; x3 = lambda^2
    lea rdi, [rsp + 64]          ; lambda^2 (reuse t2 slot)
    lea rsi, [rsp + 32]          ; lambda
    call fe_sqr

    ; x3 = lambda^2 - x1 - x1 = lambda^2 - 2*x1
    lea rdi, [rsp + 64]
    lea rsi, [rsp + 64]
    mov rdx, r13
    call fe_sub
    lea rdi, [rsp + 64]
    lea rsi, [rsp + 64]
    mov rdx, r13
    call fe_sub

    ; t0 = x1 - x3
    lea rdi, [rsp]               ; t0
    mov rsi, r13                 ; x1
    lea rdx, [rsp + 64]          ; x3
    call fe_sub

    ; t0 = lambda * (x1 - x3)
    lea rdi, [rsp]
    lea rsi, [rsp]               ; t0
    lea rdx, [rsp + 32]          ; lambda
    call fe_mul

    ; y3 = t0 - y1
    mov rdi, r12
    add rdi, 32
    lea rsi, [rsp]               ; t0
    mov rdx, r13
    add rdx, 32                  ; y1
    call fe_sub

    ; x3 -> result.x
    mov rdi, r12
    lea rsi, [rsp + 64]
    call _cpy32

.epd_done:
    add rsp, 128
    pop r15
    pop r14
    pop r13
    pop r12
    ret


; Affine point addition: P + Q
; rdi = result (x,y), rsi = P (x,y), rdx = Q (x,y)
ecc_point_add:
    push rdi
    push rsi
    push rdx
    call _ecc_point_add_internal
    pop rdx
    pop rsi
    pop rdi
    ret


; Scalar multiplication: result = k * P using Montgomery ladder
; rdi = result (x,y), rsi = k (4 limbs), rdx = P (x,y)
ecc_scalar_mult:
    push r12
    push r13
    push r14
    push r15
    sub rsp, 256                 ; R0.x, R0.y, R1.x, R1.y = 4*32+extra

    mov r12, rdi                 ; result
    mov r13, rsi                 ; k
    mov r14, rdx                 ; P

    ; R0 = infinity (x=0, y=0)
    lea rdi, [rsp]               ; R0.x
    xor eax, eax
    mov [rdi], rax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    lea rdi, [rsp + 32]          ; R0.y
    mov [rdi], rax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax

    ; R1 = P
    lea rdi, [rsp + 64]          ; R1.x
    mov rsi, r14                 ; P.x
    call _cpy32
    lea rdi, [rsp + 96]          ; R1.y
    mov rsi, r14
    add rsi, 32                  ; P.y
    call _cpy32

    ; Montgomery ladder: for each bit of k from 254 down to 0
    ; Read k from [r13] as 4 limbs

    mov r15d, 255                ; bit counter

.esm_loop:
    ; Extract bit r15d from k at [r13]
    mov ecx, r15d
    shr ecx, 6                   ; which limb (0..3)
    mov r8, [r13 + rcx*8]
    mov ecx, r15d
    and ecx, 63
    mov r9, r8
    shr r9, cl
    and r9, 1                    ; r9 = k_bit

    test r9, r9
    jz .esm_bit0

    ; bit = 1: R0 = R0 + R1, R1 = 2*R1
    ; R0 = R0 + R1
    lea rdi, [rsp]               ; R0
    lea rsi, [rsp]               ; R0
    lea rdx, [rsp + 64]          ; R1
    push r15
    call _ecc_point_add_internal
    pop r15

    ; R1 = 2*R1
    lea rdi, [rsp + 64]          ; R1
    lea rsi, [rsp + 64]          ; R1
    push r15
    call ecc_point_double
    pop r15
    jmp .esm_next

.esm_bit0:
    ; bit = 0: R1 = R0 + R1, R0 = 2*R0
    ; R1 = R0 + R1
    lea rdi, [rsp + 64]          ; R1
    lea rsi, [rsp]               ; R0
    lea rdx, [rsp + 64]          ; R1
    push r15
    call _ecc_point_add_internal
    pop r15

    ; R0 = 2*R0
    lea rdi, [rsp]               ; R0
    lea rsi, [rsp]               ; R0
    push r15
    call ecc_point_double
    pop r15

.esm_next:
    dec r15d
    jns .esm_loop

    ; Result is in R0 (or infinity)
    mov rdi, r12
    lea rsi, [rsp]               ; R0.x
    call _cpy32
    mov rdi, r12
    add rdi, 32
    lea rsi, [rsp + 32]          ; R0.y
    call _cpy32

    add rsp, 256
    pop r15
    pop r14
    pop r13
    pop r12
    ret


; Scalar multiplication by generator: result = k * G
; rdi = result (x,y), rsi = k (4 limbs)
ecc_scalar_mult_base:
    push rsi
    push rdi

    lea rdx, [rel p256_Gx]       ; P = G
    call ecc_scalar_mult

    pop rdi
    pop rsi
    ret
