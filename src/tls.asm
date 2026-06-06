; TLS code

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

; Handshake message types (RFC 5246 §7.4)
HS_CLIENT_HELLO        equ 1
HS_SERVER_HELLO        equ 2
HS_CERTIFICATE         equ 11
HS_SERVER_HELLO_DONE   equ 14

; Handshake client states
HS_WAIT_SERVER_HELLO      equ 0
HS_WAIT_CERTIFICATE       equ 1
HS_WAIT_SERVER_HELLO_DONE equ 2
HS_DONE                   equ 3

TLS_VERSION_MAJOR equ 3
TLS_VERSION_MINOR equ 3

struc tls_ctx
    .write_seq      resq 1    ; 0-7
    .read_seq       resq 1    ; 8-15
    .version        resw 1    ; 16-17
    .client_random  resb 32   ; 18-49
    .server_random  resb 32   ; 50-81
    .session_id     resb 32   ; 82-113
    .session_id_len resb 1    ; 114
    .cipher_suite   resw 1    ; 115-116
    .hs_state       resb 1    ; 117
endstruc
tls_ctx_size equ 118

extern sys_send, sys_recv
extern hmac_sha256

section .bss
header_buf:  resb TLS_HEADER_SIZE
hs_buf:  resb 4096
prf_seed_buf: resb 512
prf_abuf:     resb 32
prf_inbuf:    resb 544
prf_outbuf:   resb 32

section .text
global tls_init
global tls_send
global tls_recv
global tls_client_start
global tls_prf

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

; int tls_client_start(struct tls_ctx *ctx, int fd,
;                       const char *hostname, uint64_t hostlen)
; rdi = ctx, esi = fd, rdx = hostname, rcx = hostlen
tls_client_start:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    ; rsp+0:  recv_len (8 bytes)
    ; rsp+8:  recv_type (1 byte)

    mov r12, rdi            ; ctx
    mov r13d, esi           ; fd

    ; Set initial handshake state
    mov byte [r12 + tls_ctx.hs_state], HS_WAIT_SERVER_HELLO

    ; Generate 32 bytes of client random via getrandom (SYS 318)
    lea rdi, [r12 + tls_ctx.client_random]
    mov esi, 32
    xor edx, edx
    mov eax, 318
    syscall

    ; Build ClientHello in hs_buf
    lea rsi, [rel hs_buf]
    mov rdi, r12
    call _build_client_hello
    ; rax = message length (49)
    test rax, rax
    js .tcs_error

    ; Send as TLS Handshake record
    mov rdi, r12
    mov esi, r13d
    mov edx, TLS_HANDSHAKE
    lea rcx, [rel hs_buf]
    mov r8, rax
    call tls_send
    test rax, rax
    js .tcs_error

    ; --- Main handshake receive loop ---
.tcs_recv_loop:
    lea rdx, [rsp + 8]      ; out_type
    lea rcx, [rel hs_buf]   ; out_data
    lea r8, [rsp]           ; out_len
    mov rdi, r12
    mov esi, r13d
    call tls_recv
    test eax, eax
    jnz .tcs_error

    ; Must be a Handshake record
    cmp byte [rsp + 8], TLS_HANDSHAKE
    jne .tcs_error

    ; Parse all handshake messages in this fragment thingy
    lea r14, [hs_buf]       ; position pointer
    mov r15, [rsp]          ; remaining bytes

.tcs_parse_loop:
    cmp r15, 4
    jb .tcs_next_recv       ; need more data

    ; Read handshake message header
    movzx eax, byte [r14]           ; msg_type
    movzx ebx, byte [r14 + 1]
    shl ebx, 16
    movzx ecx, byte [r14 + 2]
    shl ecx, 8
    or ebx, ecx
    movzx ecx, byte [r14 + 3]
    or ebx, ecx                     ; ebx = message body length

    ; Total message size (including 4-byte header)
    lea ecx, [ebx + 4]
    cmp r15, rcx
    jb .tcs_next_recv               ; incomplete message

    ; Dispatch based on current handshake state
    movzx edx, byte [r12 + tls_ctx.hs_state]

    cmp dl, HS_WAIT_SERVER_HELLO
    je .tcs_handle_sh

    cmp dl, HS_WAIT_CERTIFICATE
    je .tcs_handle_cert

    cmp dl, HS_WAIT_SERVER_HELLO_DONE
    je .tcs_handle_shd

    jmp .tcs_error

.tcs_handle_sh:
    cmp al, HS_SERVER_HELLO
    jne .tcs_error

    ; Parse ServerHello body
    lea rsi, [r14 + 4]
    mov edx, ebx
    mov rdi, r12
    push r12
    push r13
    push r14
    push r15
    push rbx
    call _parse_server_hello
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    test eax, eax
    jnz .tcs_error

    mov byte [r12 + tls_ctx.hs_state], HS_WAIT_CERTIFICATE
    jmp .tcs_advance

.tcs_handle_cert:
    cmp al, HS_CERTIFICATE
    jne .tcs_error

    ; Skip Certificate body for now (Might do it later)
    mov byte [r12 + tls_ctx.hs_state], HS_WAIT_SERVER_HELLO_DONE
    jmp .tcs_advance

.tcs_handle_shd:
    cmp al, HS_SERVER_HELLO_DONE
    jne .tcs_error

    ; ServerHelloDone body must be empty aka length = 0
    test ebx, ebx
    jnz .tcs_error

    mov byte [r12 + tls_ctx.hs_state], HS_DONE
    jmp .tcs_advance

.tcs_advance:
    lea ecx, [ebx + 4]              ; total current message size
    sub r15, rcx
    add r14, rcx

    ; Check if handshake complete
    cmp byte [r12 + tls_ctx.hs_state], HS_DONE
    je .tcs_done

    test r15, r15
    jnz .tcs_parse_loop             ; more messages in this fragment

.tcs_next_recv:
    jmp .tcs_recv_loop              ; get next TLS record

.tcs_done:
    xor eax, eax
    jmp .tcs_return

.tcs_error:
    or eax, -1

.tcs_return:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret


; Build a ClientHello handshake message (RFC 5246 §7.4.1.2).
; rdi = ctx, rsi = output buffer
; Returns total message length in rax (49 bytes).
; Clobbers only caller-saved registers (rax, rcx, rdx, rdi, rsi, r8-r11).
_build_client_hello:
    cmp byte [rdi + tls_ctx.hs_state], 0
    mov rax, -1
    js .bch_error

    push r8
    push r9
    push r10
    push r11

    ; Handshake header
    mov byte [rsi], HS_CLIENT_HELLO
    mov byte [rsi + 1], 0          ; length hi = 0
    mov byte [rsi + 2], 0          ; length mid = 0
    mov byte [rsi + 3], 45         ; length lo = 45 (body size)

    ; Protocol version: TLS 1.2 (0x0303)
    mov word [rsi + 4], 0x0303

    ; Client random (32 bytes at ctx offset of 18)
    mov r8, [rdi + tls_ctx.client_random]
    mov [rsi + 6], r8
    mov r8, [rdi + tls_ctx.client_random + 8]
    mov [rsi + 14], r8
    mov r8, [rdi + tls_ctx.client_random + 16]
    mov [rsi + 22], r8
    mov r8, [rdi + tls_ctx.client_random + 24]
    mov [rsi + 30], r8

    ; Session ID length is 0
    mov byte [rsi + 38], 0

    ; Cipher suites length is 4 (big-endian)
    mov word [rsi + 39], 0x0004

    ; Cipher suite 1: TLS_RSA_WITH_AES_128_CBC_SHA (0x002F)
    mov word [rsi + 41], 0x002F
    ; Cipher suite 2: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
    mov word [rsi + 43], 0x0035

    ; Compression methods length is 1
    mov byte [rsi + 45], 1
    ; Compression method: null (0x00)
    mov byte [rsi + 46], 0

    ; Extensions length is 0
    mov word [rsi + 47], 0

    mov eax, 49                   ; total message length

.bch_return:
    pop r11
    pop r10
    pop r9
    pop r8
    ret

.bch_error:
    mov eax, -1
    jmp .bch_return


; Parse ServerHello body and update ctx fields (RFC 5246 §7.4.1.3).
; rdi = ctx, rsi = body pointer, rdx = body length
; Returns 0 on success, negative on error.
; Clobbers only caller-saved registers (rax, rcx, rdx, rdi, rsi, r8-r11).
_parse_server_hello:
    cmp rdx, 35
    jb .psh_error

    push r8
    push r9
    push r10
    push r11

    ; Save ctx and body pointer
    mov r10, rdi                 ; ctx
    mov r11, rsi                 ; body pointer

    ; Version at [r11+0] (2 bytes) - skip for now

    ; Copy server random: body bytes 2-33 → ctx.server_random
    mov r8, [r11 + 2]
    mov [r10 + tls_ctx.server_random], r8
    mov r8, [r11 + 10]
    mov [r10 + tls_ctx.server_random + 8], r8
    mov r8, [r11 + 18]
    mov [r10 + tls_ctx.server_random + 16], r8
    mov r8, [r11 + 26]
    mov [r10 + tls_ctx.server_random + 24], r8

    ; Session ID length at body offset of 34 (after 2-byte version + 32-byte random)
    movzx eax, byte [r11 + 34]
    mov [r10 + tls_ctx.session_id_len], al

    mov ecx, 35                    ; current offset in body

    test al, al
    jz .psh_no_sid

    cmp al, 32
    ja .psh_error

    ; Copy session ID (al = length)
    movzx ecx, al
    lea rdi, [r10 + tls_ctx.session_id]
    push rsi
    mov rsi, r11
    add rsi, 35                    ; source = body + 35
    rep movsb
    pop rsi

    ; Advance offset past session ID
    movzx eax, byte [r10 + tls_ctx.session_id_len]
    lea ecx, [eax + 35]

.psh_no_sid:
    ; Cipher suite (2 bytes, big-endian) at body offset ecx
    mov ax, [r11 + rcx]
    xchg al, ah                    ; big-endian → host order
    mov [r10 + tls_ctx.cipher_suite], ax
    lea ecx, [rcx + 2]             ; past cipher suite

    ; Compression method (1 byte) - skip
    lea ecx, [rcx + 1]

    ; Extensions - skip entirely for now
    ; (if body has more data, it's extensions we don't parse it)

    xor eax, eax
    jmp .psh_return

.psh_error:
    or eax, -1

.psh_return:
    pop r11
    pop r10
    pop r9
    pop r8
    ret

; TLS 1.2 PRF (RFC 5246 §5)
; P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) ||
;                        HMAC_hash(secret, A(2) + seed) || ...
; A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
; PRF(secret, label, seed) = P_hash(secret, label + seed)
;
; void tls_prf(const void *secret, uint64_t secret_len,
;              const void *label, uint64_t label_len,
;              const void *seed, uint64_t seed_len,
;              void *output, uint64_t output_len)
; rdi=secret, rsi=secret_len, rdx=label, rcx=label_len
; r8=seed, r9=seed_len
; [rsp]=ret addr, [rsp+8]=output, [rsp+16]=output_len (at entry)
tls_prf:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    ; [rsp+48] = ret addr
    ; [rsp+56] = output
    ; [rsp+64] = output_len

    mov r12, rdi              ; secret
    mov r13, rsi              ; secret_len
    mov r14, rdx              ; label
    mov r15, rcx              ; label_len
                              ; r8 = seed,  r9 = seed_len

    ; Build seed_buf = label + seed
    lea rbx, [rel prf_seed_buf]

    mov rdi, rbx
    mov rsi, r14
    mov rcx, r15
    cld
    rep movsb

    mov rsi, r8
    mov rcx, r9
    rep movsb

    ; seed_buf_len = label_len + seed_len
    mov rbp, r15
    add rbp, r9               ; rbp = seed_buf_len

    ; Compute A(1) = HMAC-SHA256(secret, seed_buf)
    mov rdi, r12
    mov rsi, r13
    lea rdx, [rel prf_seed_buf]
    mov rcx, rbp
    lea r8, [rel prf_abuf]
    call hmac_sha256

    ; Main P_SHA256 loop
    mov r14, [rsp + 56]       ; output pointer
    mov r15, [rsp + 64]       ; output_len remaining

.prf_loop:
    test r15, r15
    jz .prf_done

    ; Build inbuf = A + seed_buf
    lea rdi, [rel prf_inbuf]
    lea rsi, [rel prf_abuf]
    mov rcx, 32
    rep movsb

    lea rsi, [rel prf_seed_buf]
    mov rcx, rbp
    rep movsb

    ; HMAC-SHA256(secret, inbuf) -> outbuf
    mov rdi, r12
    mov rsi, r13
    lea rdx, [rel prf_inbuf]
    lea rcx, [rbp + 32]       ; inbuf_len = 32 + seed_buf_len
    lea r8, [rel prf_outbuf]
    call hmac_sha256

    ; Copy min(32, remaining) bytes to output
    cmp r15, 32
    jb .prf_partial

    lea rsi, [rel prf_outbuf]
    mov rdi, r14
    mov rcx, 32
    rep movsb
    mov r14, rdi
    sub r15, 32
    jmp .prf_next

.prf_partial:
    lea rsi, [rel prf_outbuf]
    mov rdi, r14
    mov rcx, r15
    rep movsb
    xor r15, r15

.prf_next:
    test r15, r15
    jz .prf_done

    ; A(i+1) = HMAC-SHA256(secret, A(i))
    mov rdi, r12
    mov rsi, r13
    lea rdx, [rel prf_abuf]
    mov rcx, 32
    lea r8, [rel prf_abuf]    ; overwrite A buffer
    call hmac_sha256

    jmp .prf_loop

.prf_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
