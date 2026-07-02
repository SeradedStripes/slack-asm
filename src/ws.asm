; WebSocket client (RFC 6455)
; Minimal implementation: send/receive frames over TLS.
BITS 64
default rel

WS_TEXT  equ 0x1
WS_CLOSE equ 0x8
WS_PING  equ 0x9
WS_PONG  equ 0xA

TLS_APPLICATION_DATA equ 23

section .bss
ws_hdr:    resb 16        ; max WebSocket frame header space
ws_sbuf:   resb 16384     ; send/receive buffer
ws_rtype:  resb 1         ; received content type

section .text
global ws_send_frame
global ws_recv_frame

extern tls_send, tls_recv

; int ws_send_frame(struct tls_ctx *ctx, int fd,
;                   uint8_t opcode, const void *data, uint64_t len)
; Builds and sends a single WebSocket frame (FIN=1, MASK=1).
; rdi=ctx, esi=fd, edx=opcode, rcx=data, r8=len
; Returns 0 on success, negative on error.
ws_send_frame:
    push r12
    push r13
    push r14
    push r15
    push rbx

    mov r12, rdi
    mov r13d, esi
    mov r14d, edx              ; opcode
    mov r15, rcx               ; data ptr
    mov rbx, r8                ; data len

    ; ---- Build frame header at ws_hdr ----
    xor eax, eax
    mov [rel ws_hdr], rax
    mov [rel ws_hdr + 8], rax

    ; Byte 0: FIN | opcode
    mov al, 0x80
    or al, r14b
    mov [rel ws_hdr], al

    ; Generate 4-byte masking key at ws_hdr + 12
    lea rdi, [rel ws_hdr + 12]
    mov esi, 4
    xor edx, edx
    mov eax, 318
    syscall

    ; Byte 1+: MASK=1 + payload length
    lea r14, [rel ws_hdr + 1]   ; write pointer
    mov rax, rbx

    cmp rax, 125
    ja .wsf_16

    mov byte [r14], 0x80
    or [r14], al
    add r14, 1
    jmp .wsf_body

.wsf_16:
    cmp rax, 65535
    ja .wsf_64

    mov byte [r14], 0xFE       ; MASK=1, len=126
    add r14, 1
    mov ax, bx
    xchg al, ah
    mov [r14], ax
    add r14, 2
    jmp .wsf_body

.wsf_64:
    mov byte [r14], 0xFF       ; MASK=1, len=127
    add r14, 1
    mov rax, rbx
    bswap rax
    mov [r14], rax
    add r14, 8

.wsf_body:
    ; Copy 4-byte mask key after the length field(s)
    mov eax, [rel ws_hdr + 12]
    mov [r14], eax
    add r14, 4

    ; r14 points past header = start of where payload goes in ws_sbuf
    ; Copy header to ws_sbuf
    lea rdi, [rel ws_sbuf]
    lea rsi, [rel ws_hdr]
    sub r14, rsi               ; r14 = header length
    mov rcx, r14
    cld
    rep movsb

    ; Copy payload into ws_sbuf after header
    mov rsi, r15
    mov rcx, rbx
    rep movsb

    ; Mask payload in-place: XOR with key bytes cyclically
    lea rdi, [rel ws_sbuf]
    add rdi, r14               ; rdi = payload start
    lea rsi, [rel ws_hdr + 12] ; mask key base
    xor ecx, ecx               ; byte index
.wsf_mask:
    cmp rcx, rbx
    jae .wsf_send
    mov al, [rdi + rcx]
    mov edx, ecx
    and edx, 3
    xor al, [rsi + rdx]
    mov [rdi + rcx], al
    inc rcx
    jmp .wsf_mask

.wsf_send:
    ; Send ws_sbuf (header + masked payload) via TLS
    lea rdi, [rel ws_sbuf]
    lea r8d, [r14d + ebx]        ; total length
    mov rcx, rdi
    mov rdi, r12
    mov esi, r13d
    mov edx, TLS_APPLICATION_DATA
    call tls_send
    test rax, rax
    js .wsf_err

    xor eax, eax
    jmp .wsf_done

.wsf_err:
    or eax, -1

.wsf_done:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    ret


; int ws_recv_frame(struct tls_ctx *ctx, int fd,
;                   uint8_t *out_type, void *data_buf, uint64_t *out_len)
; Receives a single TLS Application Data record and decodes it as a
; WebSocket frame.  The payload (after the WS header) is placed in the
; caller-supplied data_buf and *out_data is set to the start of the
; payload within that same buffer.
; rdi=ctx, esi=fd, rdx=out_type, rcx=data_buf, r8=out_len
; Returns 0 on success.
ws_recv_frame:
    push r12
    push r13
    push r14
    push r15
    push rbx
    sub rsp, 24

    mov r12, rdi
    mov r13d, esi
    mov r14, rdx               ; out_type
    mov r15, rcx               ; data_buf (caller buffer)
    mov [rsp], r8              ; out_len ptr

    ; Receive TLS record into the caller's data_buf
    lea rdx, [rel ws_rtype]
    mov rcx, r15               ; receive into data_buf directly
    lea r8, [rsp + 8]          ; recv_len (stack)
    mov rdi, r12
    mov esi, r13d
    call tls_recv
    test eax, eax
    js .wrf_err

    ; Check content type
    cmp byte [rel ws_rtype], TLS_APPLICATION_DATA
    jne .wrf_not_appdata

    mov rax, [rsp + 8]         ; recv_len
    cmp rax, 2
    jb .wrf_err

    ; Byte 0: opcode
    mov rbx, r15               ; rbx = start of received data
    movzx eax, byte [rbx]
    mov r10b, al
    and al, 0x0F
    mov [r14], al              ; *out_type = opcode

    test r10b, 0x70            ; RSV must be 0
    jnz .wrf_err

    test r10b, 0x80            ; FIN must be 1
    jz .wrf_err

    ; Byte 1: MASK + payload length
    movzx eax, byte [rbx + 1]
    mov r11b, al               ; save for MASK check
    and eax, 0x7F

    mov rbp, rax               ; rbp = payload length field

    ; Parse extended length
    lea rcx, [rbx + 2]         ; position after first 2 header bytes

    cmp rbp, 126
    je .wrf_len_16
    cmp rbp, 127
    je .wrf_len_64
    jmp .wrf_have_len

.wrf_len_16:
    mov ax, [rcx]
    xchg al, ah
    mov rbp, rax
    add rcx, 2
    jmp .wrf_have_len

.wrf_len_64:
    mov rax, [rcx]
    bswap rax
    mov rbp, rax
    add rcx, 8

.wrf_have_len:
    push rbp                   ; save payload length on stack

    test r11b, 0x80            ; MASK bit (server should NOT mask)
    jnz .wrf_masked

    ; Move payload to start of data_buf (src = data_buf + header_len)
    sub rcx, rbx               ; rcx = header length
    mov rdi, r15               ; dest = data_buf
    mov rsi, r15
    add rsi, rcx               ; src = data_buf + header_len
    pop rcx                    ; rcx = payload length (was rbp pushed above)
    cld
    rep movsb

    ; Set out_data = data_buf (payload is now at start)
    mov rax, [rsp]
    mov [rax], rbp             ; *out_len = payload length (rbp still has it)

    xor eax, eax
    jmp .wrf_done

.wrf_masked:
    ; Skip 4-byte mask key, then move payload forward same as unmasked
    add rcx, 4
    sub rcx, rbx               ; rcx = header length incl. mask key
    mov rdi, r15
    mov rsi, r15
    add rsi, rcx
    pop rcx                    ; rcx = payload length
    cld
    rep movsb

    mov rax, [rsp]
    mov [rax], rbp             ; *out_len = payload length (rbp still has it)
    xor eax, eax
    jmp .wrf_done

.wrf_not_appdata:
    mov byte [r14], 0
    mov rax, [rsp]
    mov qword [rax], 0
    xor eax, eax
    jmp .wrf_done

.wrf_err:
    or eax, -1

.wrf_done:
    add rsp, 24
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    ret