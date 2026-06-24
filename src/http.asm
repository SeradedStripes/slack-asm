; HTTP/1.1 request builder and response parser
BITS 64
default rel

section .bss
http_body_ptr:  resq 1
http_body_len:  resq 1
http_status:    resd 1

section .text
global http_start_request
global http_add_header
global http_add_content_length
global http_finish_headers
global http_add_body
global http_parse_response
global http_body_ptr
global http_body_len
global http_status

; Write decimal uint64 at [rdi], advance rdi past it, return bytes written in rax
; rdi = buf, rsi = value. Clobbers: rcx, rdx, rsi, r8
_put_uint64:
    push rbx
    push rdi

    mov rax, rsi
    mov rbx, 10
    xor ecx, ecx

    test rax, rax
    jnz .pu_loop

    mov byte [rdi], '0'
    mov eax, 1
    inc rdi
    pop rdi
    pop rbx
    ret

.pu_loop:
    xor edx, edx
    div rbx
    push rdx
    inc ecx
    test rax, rax
    jnz .pu_loop

    mov r8d, ecx
    mov rdi, [rsp + r8*8]

.pu_write:
    pop rdx
    add dl, '0'
    mov [rdi], dl
    inc rdi
    dec r8
    jnz .pu_write

    mov eax, ecx
    pop rdi
    pop rbx
    ret


; Write "METHOD /path HTTP/1.1\r\n" to [rdi]
; rdi = buf, rsi = method, rdx = method_len, rcx = path, r8 = path_len
; Returns rax = bytes written
http_start_request:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rbx, r8

    test r14, r14
    jz .hsr_err
    test rbx, rbx
    jz .hsr_err

    mov rsi, r13
    mov rcx, r14
    rep movsb

    mov byte [rdi], ' '
    inc rdi

    mov rsi, r15
    mov rcx, rbx
    rep movsb

    mov dword [rdi], ' HT'
    mov dword [rdi + 3], 'TP/'
    mov dword [rdi + 6], '1.1'
    mov word [rdi + 9], 0x0A0D
    add rdi, 11

    sub rdi, r12
    mov eax, edi
    jmp .hsr_done

.hsr_err:
    xor eax, eax

.hsr_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; Write "Name: value\r\n" at [rdi]
; rdi = buf, rsi = name, rdx = name_len, rcx = value, r8 = value_len
; Returns rax = bytes written
http_add_header:
    push r12
    push r13
    push rbx

    mov r12, rdi
    mov r13, rsi
    mov rbx, rdx

    test rbx, rbx
    jz .ah_err

    push rcx
    push r8

    mov rsi, r13
    mov rcx, rbx
    rep movsb

    mov byte [rdi], ':'
    inc rdi
    mov byte [rdi], ' '
    inc rdi

    pop rcx
    pop rsi
    test rcx, rcx
    jz .ah_crlf
    rep movsb

.ah_crlf:
    mov word [rdi], 0x0A0D
    add rdi, 2

    sub rdi, r12
    mov eax, edi

.ah_done:
    pop rbx
    pop r13
    pop r12
    ret

.ah_err:
    add rsp, 16
    xor eax, eax
    jmp .ah_done


; Write "Content-Length: NNN\r\n" at [rdi]
; rdi = buf, rsi = length (uint64)
; Returns rax = bytes written
http_add_content_length:
    push r12

    mov r12, rdi

    mov dword [rdi], 'Cont'
    mov dword [rdi + 4], 'ent-'
    mov dword [rdi + 8], 'Leng'
    mov dword [rdi + 12], 'th: '
    add rdi, 16

    push r12
    call _put_uint64
    pop r12
    add rdi, rax

    mov word [rdi], 0x0A0D
    add rdi, 2

    sub rdi, r12
    mov eax, edi

    pop r12
    ret


; Write "\r\n" at [rdi]
; Returns rax = 2
http_finish_headers:
    mov word [rdi], 0x0A0D
    mov eax, 2
    ret


; Write "\r\n" then body at [rdi]
; rdi = buf, rsi = body, rdx = body_len
; Returns rax = bytes written
http_add_body:
    push r12
    push r13

    mov r12, rdi
    mov r13, rdx

    mov word [rdi], 0x0A0D
    add rdi, 2

    test r13, r13
    jz .ab_done

    mov rcx, r13
    rep movsb

.ab_done:
    sub rdi, r12
    mov eax, edi

    pop r13
    pop r12
    ret


; Parse HTTP/1.1 response.
; rdi = response buffer, rsi = buffer length
; Extracts status code, finds Content-Length, locates body.
; Sets http_body_ptr, http_body_len, http_status.
; Returns rax = status code, or negative on error.
http_parse_response:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi              ; buf start
    mov r13, rsi              ; buf len
    xor r14d, r14d            ; content-length found (0 = not found)

    ; Minimum valid response: "HTTP/1.1 XXX\r\n" = 15 bytes
    cmp r13, 15
    jb .hpr_err

    ; Parse "HTTP/1.1 "
    cmp dword [rdi], 'HTTP'
    jne .hpr_err
    cmp dword [rdi + 4], '/1.1'
    jne .hpr_err
    cmp byte [rdi + 8], ' '
    jne .hpr_err

    lea r15, [rdi + 9]        ; r15 = status code start

    ; Parse status code (3 digits)
    movzx eax, byte [r15]
    sub eax, '0'
    cmp eax, 9
    ja .hpr_err
    imul eax, 100

    movzx ecx, byte [r15 + 1]
    sub ecx, '0'
    cmp ecx, 9
    ja .hpr_err
    imul ecx, 10
    add eax, ecx

    movzx ecx, byte [r15 + 2]
    sub ecx, '0'
    cmp ecx, 9
    ja .hpr_err
    add eax, ecx

    mov [rel http_status], eax

    ; Skip status line to find \r\n
    ; Status line is at most ~50 bytes
    lea rsi, [r15 + 3]        ; start of reason phrase
    mov rbp, r13
    sub rbp, 3                ; remaining
    sub rsi, r12              ; offset from buf start

    lea rdi, [r12 + 12]       ; skip "HTTP/1.1 XXX"
    mov rcx, r13
    sub rcx, 12
    jbe .hpr_err

.hpr_skip_reason:
    cmp byte [rdi], 0x0D
    jne .hpr_skip_next
    cmp byte [rdi + 1], 0x0A
    je .hpr_found_reason
.hpr_skip_next:
    inc rdi
    dec rcx
    jnz .hpr_skip_reason
    jmp .hpr_err

.hpr_found_reason:
    add rdi, 2                ; skip \r\n
    sub rcx, 2
    jbe .hpr_eoh              ; no headers, body starts after blank line

    ; Check for \r\n (blank line = end of headers, no headers present)
    cmp byte [rdi], 0x0D
    jne .hpr_header_loop
    cmp byte [rdi + 1], 0x0A
    je .hpr_eoh

    ; Parse headers looking for Content-Length
.hpr_header_loop:

.hpr_check_content_length:
    cmp dword [rdi], 'Cont'
    jne .hpr_skip_line
    cmp dword [rdi + 4], 'ent-'
    jne .hpr_skip_line
    cmp dword [rdi + 8], 'Leng'
    jne .hpr_skip_line
    cmp byte [rdi + 12], 't'
    jne .hpr_skip_line
    cmp byte [rdi + 13], 'h'
    jne .hpr_skip_line
    cmp byte [rdi + 14], ':'
    jne .hpr_skip_line

    lea rsi, [rdi + 15]
.hpr_cl_skip_ws:
    movzx eax, byte [rsi]
    cmp eax, '0'
    jb .hpr_cl_skip_char
    cmp eax, '9'
    ja .hpr_cl_skip_char

    mov r14d, 1
    xor r15d, r15d
    jmp .hpr_cl_digits

.hpr_cl_skip_char:
    cmp eax, 0x0D
    je .hpr_skip_line
    inc rsi
    jmp .hpr_cl_skip_ws

.hpr_cl_digits:
    movzx eax, byte [rsi]
    cmp eax, '0'
    jb .hpr_cl_done
    cmp eax, '9'
    ja .hpr_cl_done
    sub eax, '0'
    imul r15d, 10
    add r15d, eax
    inc rsi
    jmp .hpr_cl_digits

.hpr_cl_done:

.hpr_skip_line:
    ; Skip to next line
    cmp byte [rdi], 0x0D
    je .hpr_skip_crlf_try
    inc rdi
    dec rcx
    jnz .hpr_header_loop
    jmp .hpr_eoh

.hpr_skip_crlf_try:
    cmp byte [rdi + 1], 0x0A
    jne .hpr_skip_line_cont
    add rdi, 2
    sub rcx, 2
    ; Check if this was the blank line
    cmp byte [rdi], 0x0D
    je .hpr_eoh
    cmp rcx, 4
    jb .hpr_eoh
    jmp .hpr_header_loop

.hpr_skip_line_cont:
    inc rdi
    dec rcx
    jnz .hpr_header_loop

.hpr_eoh:
    ; rdi points to start of blank line \r\n (or after headers \r\n)
    ; Skip \r\n to get to body
    cmp byte [rdi], 0x0D
    jne .hpr_body_start
    cmp byte [rdi + 1], 0x0A
    jne .hpr_body_start
    add rdi, 2

.hpr_body_start:
    ; Body starts at rdi
    mov [rel http_body_ptr], rdi

    test r14d, r14d
    jz .hpr_remaining
    mov [rel http_body_len], r15d
    mov eax, [rel http_status]
    jmp .hpr_done

.hpr_remaining:
    ; No Content-Length: use remaining buffer
    sub rdi, r12
    mov rax, r13
    sub rax, rdi
    mov [rel http_body_len], rax
    mov eax, [rel http_status]
    jmp .hpr_done

.hpr_err:
    or eax, -1

.hpr_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
