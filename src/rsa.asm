; RSA public-key encryption (PKCS#1 v1.5)
; Big-integer arithmetic for 2048-bit RSA.
;
; Multi-limb integers are uint64_t arrays in little-endian order:
;   limb[0] = bits 0..63 (least significant)

BITS 64
default rel

global big_cmp, big_sub, big_add, big_mul, big_mod, big_mod_pow
global pkcs1_v15_encode, be_to_le, le_to_be, rsa_pub_encrypt

extern server_pubkey_n, server_pubkey_n_len
extern server_pubkey_e, server_pubkey_e_len

section .bss
align 8
rsa_scratch:  resb 4096

section .text

; -----------------------------------------------------------------------
;  big_cmp  —  compare a[0..n-1] vs b[0..n-1]
;  rdi = a,  rsi = b,  edx = n
;  returns eax = -1 (a<b), 0 (a==b), 1 (a>b)
; -----------------------------------------------------------------------
big_cmp:
.bc_loop:
    dec  edx
    mov  rax, [rdi + rdx*8]
    mov  r10, [rsi + rdx*8]
    cmp  rax, r10
    ja   .bc_gt
    jb   .bc_lt
    test edx, edx
    jnz  .bc_loop
    xor  eax, eax
    ret
.bc_gt:
    mov  eax, 1
    ret
.bc_lt:
    mov  eax, -1
    ret

; -----------------------------------------------------------------------
;  big_sub  —  a -= b   (in-place)
;  rdi = a,  rsi = b,  edx = n   → returns borrow
; -----------------------------------------------------------------------
big_sub:
    xor  ecx, ecx
    xor  eax, eax           ; eax = saved borrow (init 0)
.bs_loop:
    mov  r8,  [rsi + rcx*8]
    mov  r10, [rdi + rcx*8]
    bt   rax, 0             ; CF = saved borrow (rax is 0 or 1)
    sbb  r10, r8
    mov  [rdi + rcx*8], r10
    setc al                 ; save new borrow
    inc  ecx
    cmp  ecx, edx
    jb   .bs_loop
    ret

; -----------------------------------------------------------------------
;  big_add  —  a += b   (in-place)
;  rdi = a,  rsi = b,  edx = n   → returns carry
; -----------------------------------------------------------------------
big_add:
    xor  ecx, ecx
    xor  eax, eax
.ba_loop:
    mov  r8,  [rsi + rcx*8]
    mov  r10, [rdi + rcx*8]
    bt   rax, 0             ; CF = saved carry
    adc  r10, r8
    mov  [rdi + rcx*8], r10
    setc al
    inc  ecx
    cmp  ecx, edx
    jb   .ba_loop
    ret

; -----------------------------------------------------------------------
;  big_mul  —  r = a * b  (full product, 2n limbs)
;  rdi = r,  rsi = a,  rdx = b,  ecx = n
; -----------------------------------------------------------------------
big_mul:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15d, ecx

    ; zero result (2n qwords)
    xor  eax, eax
    mov  rdi, r12
    mov  rcx, r15
    shl  rcx, 1
    cld
    rep  stosq

    xor  ebx, ebx
.bm_outer:
    cmp  ebx, r15d
    jae  .bm_done
    mov  rax, [r13 + rbx*8]
    test rax, rax
    jz   .bm_next_i

    xor  r8d, r8d
    xor  r9d, r9d
.bm_inner:
    mov  r10, [r14 + r9*8]
    mov  rax, [r13 + rbx*8]
    mul  r10
    lea  r11, [rbx + r9]
    add  rax, [r12 + r11*8]
    adc  rdx, 0
    add  rax, r8
    adc  rdx, 0
    mov  [r12 + r11*8], rax
    mov  r8, rdx
    inc  r9d
    cmp  r9d, r15d
    jb   .bm_inner
    lea  r11, [rbx + r15]
    mov  [r12 + r11*8], r8
.bm_next_i:
    inc  ebx
    jmp  .bm_outer
.bm_done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

big_mod:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 280          ; 264 bytes for q*n product (33 limbs) + padding

    mov  r12, rsi           ; p (2n limbs, clobbered)
    mov  r13, rdx           ; n (modulus, n limbs)
    mov  r14d, ecx          ; nlimbs = n
    mov  r15, rdi           ; output buffer
    mov  ebx, r14d          ; start at n-1
    dec  ebx

.bm_outer:
    cmp  ebx, 0
    js   .bm_final

.bm_check_high:
    ; If p[ebx+n] > 0, multiply and subtract
    lea  ecx, [rbx + r14]
    mov  rax, [r12 + rcx*8]
    test rax, rax
    jnz  .bm_mul_sub

.bm_check_window:
    ; If p[ebx..ebx+n-1] >= n, subtract n
    lea  rdi, [r12 + rbx*8]
    mov  rsi, r13
    mov  edx, r14d
    call big_cmp
    test eax, eax
    js   .bm_next

    lea  rdi, [r12 + rbx*8]
    mov  rsi, r13
    mov  edx, r14d
    call big_sub
    test eax, eax
    jz   .bm_check_window
    ; Borrow propagated, decrement p[ebx+n] (was 0, becomes all-ones)
    lea  ecx, [rbx + r14]
    sub  qword [r12 + rcx*8], 1
    ; p[ebx+n] is now non-zero; re-check from the top
    jmp  .bm_check_high

.bm_mul_sub:
    ; Subtract q * n where q = p[ebx+n]
    ; Dont clear p[ebx+n] let subtraction handle it
    mov  rbp, rax           ; rbp = q

    ; Compute q * n into [rsp] (n+1 limbs)
    xor  r8d, r8d           ; r8 = carry
    xor  r9d, r9d           ; r9 = i
.bm_mul:
    mov  rax, [r13 + r9*8]
    mul  rbp
    add  rax, r8
    adc  rdx, 0
    mov  [rsp + r9*8], rax
    mov  r8, rdx
    inc  r9d
    cmp  r9d, r14d
    jb   .bm_mul
    mov  [rsp + r14*8], r8  ; temp[n] = final carry

    ; Subtract temp[0..n-1] from p[ebx..ebx+n-1]
    lea  rdi, [r12 + rbx*8]
    xor  ecx, ecx
    xor  r10d, r10d         ; r10 = saved borrow (init 0)
.bm_sub:
    mov  rax, [rsp + rcx*8]
    mov  r8,  [rdi + rcx*8]
    bt   r10, 0             ; CF = saved borrow
    sbb  r8,  rax
    mov  [rdi + rcx*8], r8
    setc r10b               ; save new borrow
    inc  ecx
    cmp  ecx, r14d
    jb   .bm_sub

    ; p[ebx+n] (temp[n] + borrow)
    ; Use sbb to avoid overflow when temp[n]=0xFFFFFFFFFFFFFFFF and borrow=1
    mov  rax, [rsp + r14*8]  ; temp[n]
    lea  ecx, [rbx + r14]
    bt   r10, 0              ; CF = borrow (from inner subtract loop)
    sbb  [r12 + rcx*8], rax  ; p[ebx+n] -= temp[n] + CF
    jae  .bm_check_high     ; no underflow → check if p[ebx+n] is now 0

    ; Cascade borrow upward past p[ebx+n]
    lea  r8d, [r14*2]
.bm_cascade:
    add  ecx, 1
    cmp  ecx, r8d
    jae  .bm_check_high     ; hit top of p, borrow is lost (acceptable)
    sub  qword [r12 + rcx*8], 1
    jnc  .bm_check_high
    jmp  .bm_cascade

.bm_next:
    dec  ebx
    jmp  .bm_outer

.bm_final:
    ; Ensure bottom n limbs < n (one more subtraction if needed)
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, r14d
    call big_cmp
    test eax, eax
    js   .bm_copy
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, r14d
    call big_sub

.bm_copy:
    mov  rdi, r15
    mov  rsi, r12
    mov  rcx, r14
    shl  rcx, 3
    cld
    rep  movsb

    add  rsp, 280
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; -----------------------------------------------------------------------
;  big_mod_pow  —  r = base^exp mod mod
;  rdi = r,  rsi = base,  rdx = exp,
;  ecx = explen (limbs),  r8 = modulus,  r9d = modlen (limbs)
; -----------------------------------------------------------------------
big_mod_pow:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push r8
    push r9

    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15d, ecx

    mov  rbp, r15
    shl  rbp, 6
    dec  rbp
.bmp_skip:
    mov  rax, rbp
    shr  rax, 6
    mov  ecx, ebp
    and  ecx, 63
    mov  r10, [r14 + rax*8]
    bt   r10, rcx
    jc   .bmp_found
    dec  ebp
    jns  .bmp_skip

    ; exp = 0 → result = 1
    mov  rdi, r12
    xor  eax, eax
    mov  rcx, r9
    shl  rcx, 3
    cld
    rep  stosb
    mov  qword [r12], 1
    jmp  .bmp_done

.bmp_found:
    mov  rdi, r12
    mov  rsi, r13
    mov  rcx, r9
    shl  rcx, 3
    cld
    rep  movsb

.bmp_main:
    dec  ebp
    js   .bmp_done

    ; Square: result = result * result mod mod
    lea  rdi, [rsa_scratch + 3328]
    mov  rsi, r12
    mov  rdx, r12
    mov  ecx, r9d
    call big_mul
    mov  r8, [rsp + 8]
    mov  r9, [rsp]
    mov  rdi, r12
    lea  rsi, [rsa_scratch + 3328]
    mov  rdx, r8
    mov  ecx, r9d
    call big_mod

    mov  rax, rbp
    shr  rax, 6
    mov  ecx, ebp
    and  ecx, 63
    mov  r10, [r14 + rax*8]
    bt   r10, rcx
    jnc  .bmp_main

    ; Multiply: result = result * base mod mod
    lea  rdi, [rsa_scratch + 3328]
    mov  rsi, r12
    mov  rdx, r13
    mov  ecx, r9d
    call big_mul
    mov  r8, [rsp + 8]
    mov  r9, [rsp]
    mov  rdi, r12
    lea  rsi, [rsa_scratch + 3328]
    mov  rdx, r8
    mov  ecx, r9d
    call big_mod

    jmp  .bmp_main

.bmp_done:
    pop  r9
    pop  r8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; -----------------------------------------------------------------------
; pkcs1_v15_encode  —  PKCS#1 v1.5 type 2
; rdi = out (modulus_len bytes, BE), rsi = msg, edx = msg_len, ecx = mod_len
; -----------------------------------------------------------------------
pkcs1_v15_encode:
    push rbx
    push r12
    push r13
    push r14

    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx
    mov  ebx, ecx

    lea  eax, [r14d + 11]
    cmp  eax, ebx
    ja   .pke_err

    mov  byte [r12], 0
    mov  byte [r12 + 1], 2

    mov  ebp, ebx
    sub  ebp, r14d
    sub  ebp, 3
    test ebp, ebp
    jz   .pke_pad_done

    lea  rdi, [r12 + 2]
    mov  esi, ebp
    xor  edx, edx
    mov  eax, 318
    syscall
    xor  ecx, ecx
.pke_fix:
    cmp  ecx, ebp
    jae  .pke_pad_done
    cmp  byte [r12 + 2 + rcx], 0
    jne  .pke_nf
    mov  byte [r12 + 2 + rcx], 0xff
.pke_nf:
    inc  ecx
    jmp  .pke_fix

.pke_pad_done:
    mov  eax, ebx
    sub  eax, r14d
    dec  eax
    mov  byte [r12 + rax], 0

    mov  rdi, r12
    add  rdi, rbx
    sub  rdi, r14
    mov  rsi, r13
    mov  rcx, r14
    cld
    rep  movsb

    xor  eax, eax
    jmp  .pke_done
.pke_err: or eax, -1
.pke_done:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; -----------------------------------------------------------------------
;  be_to_le  —  Convert big-endian byte array to little-endian limb array
;  rdi = dst (nlimbs qwords), rsi = src (nbytes BE bytes), edx = nbytes
;  nbytes must be multiple of 8
; -----------------------------------------------------------------------
be_to_le:
    push r12
    push r13
    push r14

    mov  r12, rdi
    mov  r13, rsi
    shr  edx, 3
    mov  r14d, edx

    xor  r9d, r9d
.btl_loop:
    cmp  r9d, r14d
    jae  .btl_done

    mov  eax, r14d
    dec  eax
    sub  eax, r9d
    shl  eax, 3
    mov  rax, [r13 + rax]
    bswap rax
    mov  [r12 + r9*8], rax

    inc  r9d
    jmp  .btl_loop
.btl_done:
    pop  r14
    pop  r13
    pop  r12
    ret

; -----------------------------------------------------------------------
;  le_to_be  —  Convert little-endian limb array to big-endian byte array
;  rdi = dst (nbytes BE bytes), rsi = src (nlimbs qwords), edx = nbytes
;  nbytes must be multiple of 8
; -----------------------------------------------------------------------
le_to_be:
    push r12
    push r13
    push r14

    mov  r12, rdi
    mov  r13, rsi
    shr  edx, 3
    mov  r14d, edx

    xor  r9d, r9d
.ltb_loop:
    cmp  r9d, r14d
    jae  .ltb_done

    mov  rax, [r13 + r9*8]
    bswap rax

    mov  ecx, r14d
    dec  ecx
    sub  ecx, r9d
    shl  ecx, 3
    mov  [r12 + rcx], rax

    inc  r9d
    jmp  .ltb_loop
.ltb_done:
    pop  r14
    pop  r13
    pop  r12
    ret

; -----------------------------------------------------------------------
;  rsa_pub_encrypt  —  c = m^e mod n  (PKCS#1 v1.5)
;  rdi = output (256 bytes, ciphertext, BE)
;  rsi = input  (plaintext)
;  rdx = input_len
; -----------------------------------------------------------------------
rsa_pub_encrypt:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8

    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx

    movzx r15d, word [server_pubkey_n_len]
    test r15d, r15d
    jz   .rpe_err

    lea  rdi, [rsa_scratch]
    mov  rsi, r13
    mov  edx, r14d
    mov  ecx, r15d
    call pkcs1_v15_encode
    test eax, eax
    jnz  .rpe_err

    mov  ebp, r15d
    shr  ebp, 3

    lea  rdi, [rsa_scratch + 2048]
    lea  rsi, [rsa_scratch]
    mov  edx, r15d
    call be_to_le

    lea  rdi, [rsa_scratch + 3072]
    lea  rsi, [server_pubkey_n]
    mov  edx, r15d
    call be_to_le

    lea  rdi, [rsa_scratch + 1024]
    xor  eax, eax
    mov  rcx, 256
    cld
    rep  stosb

    movzx ecx, word [server_pubkey_e_len]
    lea  rsi, [server_pubkey_e]
    lea  rdi, [rsa_scratch + 1024]
    xor  r9d, r9d
.rpe_exp_cp:
    cmp  r9d, ecx
    jae  .rpe_exp_done
    mov  al, [rsi + r9]
    mov  [rdi + r9], al
    inc  r9d
    jmp  .rpe_exp_cp
.rpe_exp_done:

    lea  rdi, [rsa_scratch]
    lea  rsi, [rsa_scratch + 2048]
    lea  rdx, [rsa_scratch + 1024]
    mov  ecx, ebp
    lea  r8, [rsa_scratch + 3072]
    mov  r9d, ebp
    call big_mod_pow

    mov  rdi, r12
    lea  rsi, [rsa_scratch]
    mov  edx, r15d
    call le_to_be

    xor  eax, eax
    jmp  .rpe_done

.rpe_err:
    or   eax, -1

.rpe_done:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
