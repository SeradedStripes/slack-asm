BITS 64
default rel

; TLS record layer (RFC 5246 §6.2)
;
; TLSPlaintext record format:
;   byte 0:     ContentType (20=CCS, 21=Alert, 22=Handshake, 23=AppData)
;   byte 1-2:   ProtocolVersion (major.minor, TLS 1.2 = 3.3)
;   byte 3-4:   length (big-endian)
;   byte 5+:    fragment[length]

TLS_HEADER_SIZE    equ 5
TLS_MAX_PAYLOAD    equ 16384

TLS_CHANGE_CIPHER_SPEC equ 20
TLS_ALERT              equ 21
TLS_HANDSHAKE          equ 22
TLS_APPLICATION_DATA   equ 23

TLS_VERSION_MAJOR equ 3
TLS_VERSION_MINOR equ 3

struc tls_ctx
    .write_seq resq 1
    .read_seq  resq 1
    .version   resw 1
endstruc

extern sys_send, sys_recv

section .bss
header_buf:  resb TLS_HEADER_SIZE

section .text
global tls_init
global tls_send
global tls_recv
global tls_client_start

; void tls_init(struct tls_ctx *ctx)
; rdi = ctx pointer
tls_init:
    xor eax, eax
    mov [rdi + tls_ctx.write_seq], rax
    mov [rdi + tls_ctx.read_seq], rax
    mov word [rdi + tls_ctx.version], (TLS_VERSION_MAJOR << 8) | TLS_VERSION_MINOR
    ret

; ssize_t tls_send(struct tls_ctx *ctx, int fd, int type,
;                   const void *data, uint64_t len)
; rdi = ctx, esi = fd, edx = type, rcx = data, r8 = len
; Returns total bytes written (header + data), or negative on error.
tls_send:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8                   ; stack slot for len

    mov r12, rdi               ; ctx
    mov r13d, esi              ; fd
    mov r14d, edx              ; content type
    mov r15, rcx               ; data
    mov [rsp], r8              ; save len (r8 clobbered by sys_send)

    mov r8, [rsp]              ; reload len from stack
    cmp r8, TLS_MAX_PAYLOAD
    ja .error_too_large

    ; Build 5-byte record header
    lea rbx, [rel header_buf]
    mov [rbx], r14b            ; type
    mov word [rbx + 1], (TLS_VERSION_MAJOR << 8) | TLS_VERSION_MINOR
    mov r8, [rsp]              ; reload len
    mov ax, r8w
    ror ax, 8                  ; big-endian length
    mov [rbx + 3], ax

    ; Send header
    mov edi, r13d
    mov rsi, rbx
    mov edx, TLS_HEADER_SIZE
    xor ecx, ecx               ; flags = 0
    call sys_send
    cmp rax, TLS_HEADER_SIZE
    jne .error_send

    ; Send data
    mov edi, r13d
    mov rsi, r15
    mov rdx, [rsp]             ; len (preserved on stack)
    xor ecx, ecx
    call sys_send
    cmp rax, [rsp]             ; compare with saved len
    jne .error_send

    ; Increment write sequence number
    add qword [r12 + tls_ctx.write_seq], 1

    ; Return total bytes namely header + payload
    mov rax, [rsp]
    add rax, TLS_HEADER_SIZE
    jmp .done

.error_too_large:
    mov eax, -2
    jmp .done

.error_send:
    or rax, -1

.done:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; int tls_recv(struct tls_ctx *ctx, int fd,
;              uint8_t *out_type, void *out_data, uint64_t *out_len)
; rdi = ctx, esi = fd, rdx = out_type, rcx = out_data, r8 = out_len
; Returns 0 on success and negative on error.
tls_recv:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8                   ; stack slot for out_len

    mov rbp, rdi               ; ctx (preserved across calls)
    mov r13d, esi              ; fd
    mov r14, rdx               ; out_type
    mov r15, rcx               ; out_data
    mov [rsp], r8              ; save out_len (r8 clobbered by sys_recv via _read_exactly)

    ; Read exactly 5 bytes (header)
    lea rbx, [rel header_buf]
    mov edi, r13d
    mov rsi, rbx
    mov edx, TLS_HEADER_SIZE
    call _read_exactly
    test rax, rax
    js .error_read

    ; Parse header
    movzx eax, byte [rbx]          ; content type
    mov [r14], al

    mov ax, [rbx + 3]              ; big-endian length
    ror ax, 8                      ; to host order
    movzx r12d, ax                 ; fragment length

    ; Validate length
    cmp r12d, TLS_MAX_PAYLOAD
    ja .error_bad_length

    ; Read fragment
    mov edi, r13d
    mov rsi, r15
    mov edx, r12d
    call _read_exactly
    test rax, rax
    js .error_read

    ; Store actual fragment length
    mov rax, [rsp]                ; out_len pointer (preserved on stack)
    mov [rax], r12                ; *out_len = length

    ; Increment read sequence number
    add qword [rbp + tls_ctx.read_seq], 1

    xor eax, eax
    jmp .done

.error_bad_length:
    mov eax, -3
    jmp .done

.error_read:
    or rax, -1

.done:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; ssize_t _read_exactly(int fd, void *buf, size_t count)
; Reads exactly count bytes into buf, handling partial reads.
; Returns 0 on success, negative on error (or EOF).
; rdi = fd, rsi = buf, rdx = count
_read_exactly:
    push r12
    push r13
    mov r12, rsi            ; buf
    mov r13, rdx            ; remaining count
    mov edi, edi            ; fd (zero-extend)

.loop:
    mov rsi, r12
    mov rdx, r13
    xor ecx, ecx            ; flags = 0 (syscall clobbers rcx)
    call sys_recv

    cmp rax, 0
    jle .error              ; EOF or error

    sub r13, rax            ; decrease remaining
    jz .done                ; got everything

    add r12, rax            ; advance buffer
    jmp .loop

.error:
    or rax, -1

.done:
    pop r13
    pop r12
    ret

; int tls_client_start(int fd, const char *hostname, uint64_t hostlen)
; Initiates a TLS handshake. Stub for now.
; rdi = fd, rsi = hostname, rdx = hostlen
tls_client_start:
    xor eax, eax
    ret
