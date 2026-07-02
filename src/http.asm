; HTTP/1.1 request builder and response parser
BITS 64
default rel

section .bss
http_body_ptr:  resq 1
http_body_len:  resq 1
http_status:    resd 1
http_chunked:   resb 1

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
global http_chunked
global http_decode_chunked

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


; Write body bytes at [rdi]
; Headers must be terminated by \r\n before calling this
; rdi = buf, rsi = body, rdx = body_len
; Returns rax = bytes written
http_add_body:
    push r12
    push r13

    mov r12, rdi
    mov r13, rdx

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

    ; Parse "HTTP/1.x "
    cmp dword [rdi], 'HTTP'
    jne .hpr_err
    cmp word [rdi + 4], '/1'
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
    mov byte [rel http_chunked], 0

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
    jne .hpr_check_transfer_encoding
    cmp dword [rdi + 4], 'ent-'
    jne .hpr_check_transfer_encoding
    cmp dword [rdi + 8], 'Leng'
    jne .hpr_check_transfer_encoding
    cmp byte [rdi + 12], 't'
    jne .hpr_check_transfer_encoding
    cmp byte [rdi + 13], 'h'
    jne .hpr_check_transfer_encoding
    cmp byte [rdi + 14], ':'
    jne .hpr_check_transfer_encoding

    lea rsi, [rdi + 15]
.hpr_cl_skip_ws:
    movzx eax, byte [rsi]
    cmp eax, '0'
    jb .hpr_cl_skip_char
    cmp eax, '9'
    ja .hpr_cl_skip_char

    mov r14d, 1
    xor r15, r15
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
    imul r15, 10
    add r15, rax
    inc rsi
    jmp .hpr_cl_digits

.hpr_cl_done:

.hpr_check_transfer_encoding:
    cmp dword [rdi], 'Tran'
    jne .hpr_skip_line
    cmp dword [rdi + 4], 'sfer'
    jne .hpr_skip_line
    cmp byte [rdi + 8], '-'
    jne .hpr_skip_line
    cmp dword [rdi + 9], 'Enco'
    jne .hpr_skip_line
    cmp dword [rdi + 13], 'ding'
    jne .hpr_skip_line
    cmp byte [rdi + 17], ':'
    jne .hpr_skip_line
    lea rsi, [rdi + 18]
.hpr_te_scan:
    movzx eax, byte [rsi]
    cmp eax, 0x0D
    je .hpr_skip_line
    ; fold case: OR 0x20 for lowercase
    or eax, 0x20
    cmp eax, 'c'
    jne .hpr_te_next
    cmp byte [rsi + 1], 'h'
    jne .hpr_te_next
    cmp byte [rsi + 2], 'u'
    jne .hpr_te_next
    cmp byte [rsi + 3], 'n'
    jne .hpr_te_next
    cmp byte [rsi + 4], 'k'
    jne .hpr_te_next
    cmp byte [rsi + 5], 'e'
    jne .hpr_te_next
    cmp byte [rsi + 6], 'd'
    jne .hpr_te_next
    mov byte [rel http_chunked], 1
    jmp .hpr_skip_line
.hpr_te_next:
    inc rsi
    jmp .hpr_te_scan

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
    mov [rel http_body_len], r15
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


; Decode chunked transfer encoding in-place.
; rdi = pointer to raw chunked body, rsi = length of raw body
; Returns rax = decoded body length. On error, returns -1.
; The decoded body overwrites the raw body (always <= raw length).
http_decode_chunked:
    push r12
    push r13
    push r14
    push r15

    xor eax, eax
    test rsi, rsi
    jz .hdc_done

    mov r12, rdi              ; read pointer
    mov r13, rdi              ; write pointer (same buffer, in-place)
    mov r14, rsi              ; remaining bytes in raw buffer
    xor r15d, r15d            ; decoded byte count

.hdc_chunk_loop:
    test r14, r14
    jz .hdc_done

    ; Skip optional CRLF before next chunk (after first chunk)
    cmp byte [r12], 0x0D
    jne .hdc_parse_size
    cmp r14, 2
    jb .hdc_err
    cmp byte [r12 + 1], 0x0A
    jne .hdc_err
    add r12, 2
    sub r14, 2

.hdc_parse_size:
    ; Parse hex chunk size
    xor edx, edx              ; chunk_size
    xor ecx, ecx              ; digit count
.hdc_hex_loop:
    test r14, r14
    jz .hdc_err
    movzx eax, byte [r12]
    cmp eax, 0x0D
    je .hdc_size_done
    cmp eax, ';'              ; chunk-extension
    je .hdc_skip_ext
    ; Convert hex digit
    sub eax, '0'
    cmp eax, 9
    jbe .hdc_hex_digit
    ; Try A-F or a-f
    and eax, 0xDF             ; uppercase
    sub eax, 7                ; 'A' - '0' - 10 = 7
    cmp eax, 15
    ja .hdc_err
.hdc_hex_digit:
    shl edx, 4
    add edx, eax
    inc r12
    dec r14
    inc ecx
    jmp .hdc_hex_loop

.hdc_skip_ext:
    ; Skip chunk-extension: advance to CRLF
    test r14, r14
    jz .hdc_err
    cmp byte [r12], 0x0D
    je .hdc_size_done
    inc r12
    dec r14
    jmp .hdc_skip_ext

.hdc_size_done:
    ; Skip CRLF after chunk size
    cmp r14, 2
    jb .hdc_err
    cmp word [r12], 0x0A0D
    jne .hdc_err
    add r12, 2
    sub r14, 2

    test edx, edx
    jz .hdc_last_chunk

    ; Copy chunk data from read ptr to write ptr
    cmp r14d, edx
    jb .hdc_err
    cmp r12, r13
    jbe .hdc_no_overlap
    ; If read > write, use memmove
.hdc_no_overlap:
    ; Copy chunk data from r12 to r13
    mov rsi, r12
    mov rdi, r13
    mov ecx, edx
    rep movsb
    mov r12, rsi
    mov r13, rdi
    sub r14, rdx
    add r15d, edx

    ; Skip CRLF after chunk data
    cmp r14, 2
    jb .hdc_err
    cmp word [r12], 0x0A0D
    jne .hdc_err
    add r12, 2
    sub r14, 2

    jmp .hdc_chunk_loop

.hdc_last_chunk:
    ; Skip trailers (until final CRLF)
.hdc_trailer_loop:
    cmp r14, 2
    jb .hdc_got_all          ; no more data, we have what we have
    cmp byte [r12], 0x0D
    jne .hdc_trailer_line
    cmp byte [r12 + 1], 0x0A
    jne .hdc_trailer_line
    ; Final CRLF, done
    mov eax, r15d
    jmp .hdc_done
.hdc_trailer_line:
    test r14, r14
    jz .hdc_got_all
    cmp byte [r12], 0x0D
    je .hdc_trailer_crlf
    inc r12
    dec r14
    jmp .hdc_trailer_line
.hdc_trailer_crlf:
    cmp r14, 2
    jb .hdc_err
    cmp byte [r12 + 1], 0x0A
    jne .hdc_err
    add r12, 2
    sub r14, 2
    jmp .hdc_trailer_loop

.hdc_got_all:
    mov eax, r15d
    jmp .hdc_done

.hdc_err:
    or eax, -1

.hdc_done:
    pop r15
    pop r14
    pop r13
    pop r12
    ret
