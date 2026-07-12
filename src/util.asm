; address construction and simple error handling helpers

BITS 64
default rel

%define AF_INET 2

section .bss
last_errno:    resd 1

section .text
global make_sockaddr_in
global save_errno_and_ret
global get_last_errno

; make_sockaddr_in(void *dst, uint16_t port_hostorder, uint32_t ip_hostorder)
; Writes a struct sockaddr_in of 16 bytes to dst and returns 16 in eax
make_sockaddr_in:
    ; rdi = dst, rsi = port, rdx = ip
    mov word [rdi], AF_INET

    mov ax, si
    rol ax, 8
    mov word [rdi + 2], ax

    mov eax, edx
    bswap eax
    mov dword [rdi + 4], eax

    mov qword [rdi + 8], 0

    mov eax, 16
    ret

; save_errno_and_ret
; Expects syscall return value in rax
; If rax < 0 then stores -rax into last_errno and returns -1 in eax
; Otherwise returns the original rax
save_errno_and_ret:
    cmp rax, 0
    jge .ok
    neg rax
    mov [rel last_errno], eax
    mov eax, -1
    ret
.ok:
    ret

get_last_errno:
    mov eax, [rel last_errno]
    ret

; Find a JSON string value by key.
; Searches for `"key":"` in buffer and returns pointer + length of value.
; rdi = buffer, rsi = buf_len, rdx = key (including quotes, e.g. `"url"`), rcx = key_len
; Returns rax = value pointer (into original buffer), edx = value length, or rax=0 on error
global json_get_str
json_get_str:
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi              ; buf
    mov r13, rsi              ; buf_len
    mov r14, rdx              ; key
    mov r15, rcx              ; key_len

    test r13, r13
    jz .jgs_not_found

    xor ecx, ecx              ; offset in buffer
.jgs_scan:
    cmp rcx, r13
    jae .jgs_not_found

    ; Check: offset + key_len <= buf_len
    lea rax, [rcx + r15]
    cmp rax, r13
    ja .jgs_not_found

    push rcx
    push rdi
    push rsi
    lea rdi, [r12 + rcx]
    mov rsi, r14
    mov rcx, r15
    cld
    repe cmpsb
    pop rsi
    pop rdi
    pop rcx
    je .jgs_found_key

    inc rcx
    jmp .jgs_scan

.jgs_found_key:
    ; Found key, skip past `:"`
    add rcx, r15              ; advance past key
    cmp rcx, r13
    jae .jgs_not_found
    cmp byte [r12 + rcx], ':'
    jne .jgs_not_found
    inc rcx
    cmp rcx, r13
    jae .jgs_not_found
    cmp byte [r12 + rcx], '"'
    jne .jgs_not_found
    inc rcx
    cmp rcx, r13
    jae .jgs_not_found

    ; Value starts here
    lea rax, [r12 + rcx]
    xor edx, edx
.jgs_value_loop:
    cmp rcx, r13
    jae .jgs_done
    cmp byte [r12 + rcx], '"'
    je .jgs_done
    inc rcx
    inc edx
    jmp .jgs_value_loop

.jgs_done:
    pop r15
    pop r14
    pop r13
    pop r12
    ret

.jgs_not_found:
    xor eax, eax
    xor edx, edx
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; int memmem(const char *buf, uint32_t buflen, const char *needle, uint32_t needlelen)
; Returns 1 if needle found, 0 otherwise. Clobbers rdi, rsi, rcx, rax, rdx.
global memmem
memmem:
    test ecx, ecx
    jz .mm_no
    sub esi, ecx
    jb .mm_no
    inc esi
    mov r8, rdi
    xor r9d, r9d
.mm_outer:
    cmp r9d, esi
    jae .mm_no
    mov al, [rdx]
.mm_scan:
    cmp r9d, esi
    jae .mm_no
    cmp al, [r8 + r9]
    je .mm_try
    inc r9d
    jmp .mm_scan
.mm_try:
    push rcx
    push rdi
    push rsi
    push rdx
    lea rdi, [r8 + r9]
    mov rsi, rdx
    cld
    repe cmpsb
    pop rdx
    pop rsi
    pop rdi
    pop rcx
    je .mm_yes
    inc r9d
    jmp .mm_outer
.mm_yes:
    mov eax, 1
    ret
.mm_no:
    xor eax, eax
    ret

; Base64 encode binary data (RFC 4648)
; rdi = input, rsi = input_len, rdx = output buffer
; Returns rax = encoded length
global base64_encode
base64_encode:
    push r12
    push r13
    push r14
    push r15
    push rbx

    mov r12, rdi              ; input
    mov r13, rsi              ; input_len
    mov r14, rdx              ; output
    xor r15d, r15d            ; output index

    lea rbx, [rel b64_alphabet]

.b64_loop:
    cmp r13, 3
    jb .b64_final

    ; Process 3 bytes -> 4 chars
    movzx eax, byte [r12]
    movzx ecx, byte [r12 + 1]
    movzx edx, byte [r12 + 2]
    shl eax, 16
    shl ecx, 8
    or eax, ecx
    or eax, edx

    ; First char: bits 18-23
    mov ecx, eax
    shr ecx, 18
    mov cl, [rbx + rcx]
    mov [r14 + r15], cl
    inc r15d

    ; Second char: bits 12-17
    mov ecx, eax
    shr ecx, 12
    and ecx, 0x3F
    mov cl, [rbx + rcx]
    mov [r14 + r15], cl
    inc r15d

    ; Third char: bits 6-11
    mov ecx, eax
    shr ecx, 6
    and ecx, 0x3F
    mov cl, [rbx + rcx]
    mov [r14 + r15], cl
    inc r15d

    ; Fourth char: bits 0-5
    and eax, 0x3F
    mov al, [rbx + rax]
    mov [r14 + r15], al
    inc r15d

    add r12, 3
    sub r13, 3
    jmp .b64_loop

.b64_final:
    test r13, r13
    jz .b64_done

    ; 1 or 2 remaining bytes with padding
    xor eax, eax
    xor ecx, ecx
    mov [r14 + r15 + 4], cl     ; padding space

    movzx eax, byte [r12]
    shl eax, 16
    cmp r13, 2
    jb .b64_one_byte
    movzx ecx, byte [r12 + 1]
    shl ecx, 8
    or eax, ecx

.b64_one_byte:
    ; First char
    mov ecx, eax
    shr ecx, 18
    mov cl, [rbx + rcx]
    mov [r14 + r15], cl
    inc r15d

    ; Second char
    mov ecx, eax
    shr ecx, 12
    and ecx, 0x3F
    mov cl, [rbx + rcx]
    mov [r14 + r15], cl
    inc r15d

    cmp r13, 2
    jb .b64_pad_two

    ; Third char (2 remaining bytes)
    mov ecx, eax
    shr ecx, 6
    and ecx, 0x3F
    mov cl, [rbx + rcx]
    mov [r14 + r15], cl
    inc r15d

    ; Fourth char (no padding)
    and eax, 0x3F
    mov al, [rbx + rax]
    mov [r14 + r15], al
    inc r15d
    jmp .b64_done

.b64_pad_two:
    ; Third char = padding
    mov byte [r14 + r15], '='
    inc r15d
    ; Fourth char = padding
    mov byte [r14 + r15], '='
    inc r15d

.b64_done:
    mov eax, r15d
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    ret

section .rodata
b64_alphabet: db "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

; Parse a wss:// URL into hostname and path components.
; Input:  rdi = URL string (e.g. "wss://host/path?query")
;         rsi = URL length
; Output: rax = host pointer, ecx = host length
;         r8  = path pointer, r9  = path length
;         Returns 0 on success, -1 on error.
; Clobbers: rdx
global parse_wss_url
parse_wss_url:
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi

    ; Skip "wss://" prefix
    cmp r13, 6
    jb .pwu_err
    cmp dword [r12], 'wss:'
    jne .pwu_err
    cmp word [r12 + 4], '//'
    jne .pwu_err
    add r12, 6
    sub r13, 6

    ; Find end of hostname (next '/' or end of string)
    xor ecx, ecx
.pwu_host_scan:
    cmp rcx, r13
    jae .pwu_host_end
    cmp byte [r12 + rcx], '/'
    je .pwu_host_end
    cmp byte [r12 + rcx], ':'
    je .pwu_host_port
    inc rcx
    jmp .pwu_host_scan

.pwu_host_port:
    ; Found port separator - hostname ends here
    ; Skip port (digits after ':')
    inc rcx
.pwu_port_scan:
    cmp rcx, r13
    jae .pwu_host_end
    cmp byte [r12 + rcx], '/'
    je .pwu_host_end
    cmp byte [r12 + rcx], '0'
    jb .pwu_host_end
    cmp byte [r12 + rcx], '9'
    ja .pwu_host_end
    inc rcx
    jmp .pwu_port_scan

.pwu_host_end:
    mov rax, r12              ; host ptr
    mov ecx, ecx              ; host length (already in ecx)

    ; Find start of path (skip '/')
.pwu_path_start:
    cmp rcx, r13
    jae .pwu_no_path
    lea r8, [r12 + rcx]       ; path ptr
    mov r9, r13
    sub r9, rcx               ; path length

    pop r13
    pop r12
    xor eax, eax
    ret

.pwu_no_path:
    ; No path - use "/"
    lea r8, [rel pwu_root]
    mov r9d, 1
    pop r13
    pop r12
    xor eax, eax
    ret

.pwu_err:
    xor eax, eax
    xor ecx, ecx
    xor r8, r8
    xor r9, r9
    or rax, -1
    pop r13
    pop r12
    ret

section .data
pwu_root: db "/"
