; ASN.1 DER and X.509 certificate parser
; RFC 5280

BITS 64
default rel

ASN_INTEGER         equ 0x02
ASN_BIT_STRING      equ 0x03
ASN_NULL            equ 0x05
ASN_OID             equ 0x06
ASN_UTCTIME         equ 0x17
ASN_SEQUENCE        equ 0x30
ASN_SET             equ 0x31
ASN_CONTEXT_0       equ 0xA0
ASN_CONTEXT_3       equ 0xA3

section .data
months_before:
dd 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334

section .bss
cert_not_before:    resd 1
cert_not_after:     resd 1
server_pubkey_n:    resb 256
server_pubkey_n_len: resw 1
server_pubkey_e:    resb 4
server_pubkey_e_len: resw 1

section .text
global x509_parse_cert
global x509_check_validity
global cert_not_before
global cert_not_after
global server_pubkey_n
global server_pubkey_n_len
global server_pubkey_e
global server_pubkey_e_len

; Read one DER TLV.
; rdi=cursor, rsi=remaining
; -> al=tag, ebx=valuelen, rdi=valuestart, rsi=remafterTLV, cf=0 ok
_der_read:
    test rsi, rsi
    jz .dr_err
    movzx eax, byte [rdi]
    inc rdi
    dec rsi
    test rsi, rsi
    jz .dr_err
    xor ebx, ebx
    movzx ecx, byte [rdi]
    inc rdi
    dec rsi
    test cl, 0x80
    jz .dr_short
    and ecx, 0x7F
    jz .dr_err
.dr_long:
    test rsi, rsi
    jz .dr_err
    shl ebx, 8
    movzx r8d, byte [rdi]
    or ebx, r8d
    inc rdi
    dec rsi
    dec ecx
    jnz .dr_long
    jmp .dr_got
.dr_short:
    mov ebx, ecx
.dr_got:
    cmp rsi, rbx
    jb .dr_err
    sub rsi, rbx
    clc
    ret
.dr_err:
    stc
    ret

; Expect tag, return value.
; cl=expected tag, same I/O as _der_read
_der_expect:
    mov dl, cl
    call _der_read
    jc .de_end
    cmp al, dl
    jne .de_bad
    clc
    ret
.de_bad:
    stc
.de_end:
    ret

; Read 2 ASCII digits at [rdi] -> eax
_read_2digit:
    movzx eax, byte [rdi]
    sub eax, '0'
    movzx ecx, byte [rdi + 1]
    sub ecx, '0'
    imul eax, 10
    add eax, ecx
    ret

; UTCTime (YYMMDDHHMMSSZ) -> epoch seconds.
; rdi=value, ebx=len -> eax=epoch, cf=1 err
_parse_utctime:
    push rcx
    push rdx
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    cmp ebx, 13
    jb .pt_err
    call _read_2digit
    cmp eax, 50
    jae .pt_1900
    add eax, 2000
    jmp .pt_yok
.pt_1900:
    add eax, 1900
.pt_yok:
    mov edx, eax
    add rdi, 2
    call _read_2digit
    mov r12d, eax
    cmp r12d, 1
    jb .pt_err
    cmp r12d, 12
    ja .pt_err
    add rdi, 2
    call _read_2digit
    mov r8d, eax
    cmp r8d, 1
    jb .pt_err
    cmp r8d, 31
    ja .pt_err
    add rdi, 2
    call _read_2digit
    mov r9d, eax
    cmp r9d, 23
    ja .pt_err
    add rdi, 2
    call _read_2digit
    mov r10d, eax
    cmp r10d, 59
    ja .pt_err
    add rdi, 2
    call _read_2digit
    mov r11d, eax
    cmp r11d, 59
    ja .pt_err
    add rdi, 2
    cmp byte [rdi], 'Z'
    jne .pt_err
    mov ecx, r12d
    call _datetime_epoch
    clc
    jmp .pt_done
.pt_err:
    stc
.pt_done:
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rdx
    pop rcx
    ret

; Date components -> epoch seconds
; edx=year, ecx=month, r8d=day, r9d=hour, r10d=min, r11d=sec
_datetime_epoch:
    push rcx
    push rbx
    push rdi
    ; Leap days 1970..year-1
    lea eax, [rdx - 1]
    shr eax, 2
    sub eax, 492
    ; Leap this year?
    xor ebx, ebx
    test dl, 3
    jnz .de_nl
    mov ebx, 1
.de_nl:
    cmp ecx, 2
    jg .de_ul
    xor ebx, ebx
.de_ul:
    ; Full years
    lea edi, [rdx - 1970]
    imul edi, 365
    add eax, edi
    ; Months before
    dec ecx
    lea rdi, [months_before]
    add eax, [rdi + rcx*4]
    ; Day of month
    add eax, r8d
    dec eax
    ; Leap
    add eax, ebx
    ; To seconds
    imul eax, 86400
    imul r9d, 3600
    add eax, r9d
    imul r10d, 60
    add eax, r10d
    add eax, r11d
    pop rdi
    pop rbx
    pop rcx
    ret

; ----- X.509 Certificate Parser -----
; rdi=DER data, rsi=length
; -> rax=0 ok, -1 error
x509_parse_cert:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; Certificate SEQUENCE
    mov cl, ASN_SEQUENCE
    call _der_expect
    jc .xp_err
    push rsi             ; save remaining past Certificate
    push rdi             ; save content start
    push rbx             ; save content length
    mov rsi, rbx         ; inner remaining = content length

    ; TBSCertificate SEQUENCE
    mov cl, ASN_SEQUENCE
    call _der_expect
    jc .xp_err
    push rsi
    push rdi
    push rbx
    mov rsi, rbx

    ; [0] EXPLICIT (version)
    mov cl, ASN_CONTEXT_0
    call _der_expect
    jc .xp_err
    push rsi
    push rdi
    push rbx
    mov rsi, rbx
    ; INTEGER inside [0] - skip
    call _der_read
    jc .xp_err
    add rdi, rbx
    pop rbx
    pop rdi
    add rdi, rbx
    pop rsi

    ; INTEGER (serialNumber) - skip
    call _der_read
    jc .xp_err
    add rdi, rbx

    ; SEQUENCE (signature algorithm) - skip
    call _der_read
    jc .xp_err
    add rdi, rbx

    ; SEQUENCE (issuer) - skip
    call _der_read
    jc .xp_err
    add rdi, rbx

    ; SEQUENCE (validity)
    mov cl, ASN_SEQUENCE
    call _der_expect
    jc .xp_err
    push rsi
    push rdi
    push rbx
    mov rsi, rbx

    ; UTCTime notBefore
    mov cl, ASN_UTCTIME
    call _der_expect
    jc .xp_err
    call _parse_utctime
    jc .xp_err
    mov [cert_not_before], eax
    add rdi, rbx

    ; UTCTime notAfter
    mov cl, ASN_UTCTIME
    call _der_expect
    jc .xp_err
    call _parse_utctime
    jc .xp_err
    mov [cert_not_after], eax

    ; Exit validity
    pop rbx
    pop rdi
    add rdi, rbx
    pop rsi

    ; SEQUENCE (subject) - skip
    call _der_read
    jc .xp_err
    add rdi, rbx

    ; SEQUENCE (subjectPublicKeyInfo)
    mov cl, ASN_SEQUENCE
    call _der_expect
    jc .xp_err
    push rsi
    push rdi
    push rbx
    mov rsi, rbx

    ; AlgorithmIdentifier - skip
    call _der_read
    jc .xp_err
    add rdi, rbx

    ; BIT STRING (subjectPublicKey)
    mov cl, ASN_BIT_STRING
    call _der_expect
    jc .xp_err
    push rsi
    push rdi
    push rbx
    mov rsi, rbx

    ; Skip unused bits byte
    test rsi, rsi
    jz .xp_err
    movzx eax, byte [rdi]
    test eax, eax
    jnz .xp_err
    inc rdi
    dec rsi

    ; RSAPublicKey SEQUENCE
    mov cl, ASN_SEQUENCE
    call _der_expect
    jc .xp_err
    push rsi
    push rdi
    push rbx
    mov rsi, rbx

    ; INTEGER modulus
    mov cl, ASN_INTEGER
    call _der_expect
    jc .xp_err
    push rsi             ; remaining past modulus TLV
    push rdi             ; modulus value start
    push rbx             ; modulus value length

    ; Copy modulus to BSS (strip leading 0x00)
    mov r12, rdi
    mov r13d, ebx
    movzx eax, byte [rdi]
    test eax, eax
    jnz .xp_ns_n
    inc r12
    dec r13d
.xp_ns_n:
    cmp r13w, 256
    ja .xp_err
    mov [server_pubkey_n_len], r13w
    lea rdi, [rel server_pubkey_n]
    mov rsi, r12
    mov rcx, r13
    cld
    rep movsb

    ; Restore cursor past modulus value
    pop rbx              ; original modulus value length
    pop rdi              ; original modulus value start
    add rdi, rbx         ; advance past value
    pop rsi              ; restore remaining past modulus TLV

    ; INTEGER exponent
    mov cl, ASN_INTEGER
    call _der_expect
    jc .xp_err

    ; Copy exponent to BSS
    cmp ebx, 4
    ja .xp_err
    mov [server_pubkey_e_len], bx
    push rsi
    push rdi
    push rbx
    lea rdi, [rel server_pubkey_e]
    pop rcx
    pop rsi
    cld
    rep movsb
    pop rsi


    ; Exit RSAPublicKey
    pop rbx
    pop rdi
    add rdi, rbx
    pop rsi

    ; Exit BIT STRING
    pop rbx
    pop rdi
    add rdi, rbx
    pop rsi

    ; Exit subjectPublicKeyInfo
    pop rbx
    pop rdi
    add rdi, rbx
    pop rsi

    ; Skip any remaining TBS fields (extensions, etc.)
.xp_skip_tbs:
    test rsi, rsi
    jz .xp_tbs_done
    call _der_read
    jc .xp_err
    add rdi, rbx
    jmp .xp_skip_tbs
.xp_tbs_done:

    ; Exit TBSCertificate
    pop rbx
    pop rdi
    add rdi, rbx
    pop rsi

    ; SEQUENCE (signatureAlgorithm) - skip
    call _der_read
    jc .xp_err
    add rdi, rbx

    ; BIT STRING (signatureValue) - skip for now
    call _der_read
    jc .xp_err
    add rdi, rbx

    ; Exit Certificate
    pop rbx
    pop rdi
    add rdi, rbx
    pop rsi

    xor eax, eax
    jmp .xp_done

.xp_err:
    stc
.xp_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rax, -1
    jc .xp_err_ret
    xor eax, eax
.xp_err_ret:
    ret

; Check validity: now >= notBefore && now <= notAfter
; Uses hardcoded date (2026-06-09) since this is a dev test env.
; -> rax=0 valid, -1 invalid
x509_check_validity:
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    sub rsp, 16
    mov edi, 0
    mov rsi, rsp
    mov eax, 228
    syscall
    mov eax, [rsp]
    add rsp, 16
    cmp eax, [cert_not_before]
    jb .cv_fail
    cmp eax, [cert_not_after]
    ja .cv_fail
    xor eax, eax
    jmp .cv_done
.cv_fail:
    or eax, -1
.cv_done:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    ret
