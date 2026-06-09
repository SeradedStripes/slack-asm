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
extern aes128_cbc_encrypt
extern aes128_cbc_decrypt

section .rodata
master_label:       db "master secret"
master_label_len:   equ $ - master_label
key_expansion_label: db "key expansion"
key_expansion_label_len: equ $ - key_expansion_label

section .bss
header_buf:  resb TLS_HEADER_SIZE
hs_buf:  resb 4096
prf_seed_buf: resb 512
prf_abuf:     resb 32
prf_inbuf:    resb 544
prf_outbuf:   resb 32
master_secret:     resb 48
client_write_mac_key: resb 32
server_write_mac_key: resb 32
client_write_key:  resb 16
server_write_key:  resb 16
client_write_iv:   resb 4
server_write_iv:   resb 4
aes_round_keys:    resb 176
mac_header_buf:    resb 13
record_iv:         resb 16
record_plaintext:  resb 16448  ; max fragment + 32 MAC + 16 pad

section .text
global tls_init
global tls_send
global tls_recv
global tls_client_start
global tls_prf
global tls_derive_keys
global master_secret
global client_write_key
global server_write_key
global client_write_iv
global server_write_iv
global client_write_mac_key
global server_write_mac_key

; void tls_init(struct tls_ctx *ctx)
; rdi = ctx pointer
tls_init:
    xor eax, eax
    mov [rdi + tls_ctx.write_seq], rax
    mov [rdi + tls_ctx.read_seq], rax
    mov word [rdi + tls_ctx.version], (TLS_VERSION_MAJOR << 8) | TLS_VERSION_MINOR
    ret

; Build MAC input prefix (seq_num + type + version + length)
; rdi = mac_header_buf (13 bytes output), rsi = seq_num_ptr, edx = type,
; ecx = fragment_len
_mac_prefix:
    mov rax, [rsi]
    bswap rax
    mov [rdi], rax
    mov [rdi + 8], dl
    mov word [rdi + 9], (TLS_VERSION_MAJOR << 8) | TLS_VERSION_MINOR
    mov ax, cx
    ror ax, 8
    mov [rdi + 11], ax
    ret

; Compute record-layer MAC
; rdi = mac_key (32 bytes), rsi = seq_num_ptr, edx = type,
; rcx = frag, r8 = frag_len, r9 = mac_out (32 bytes)
_tls_compute_mac:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16

    ; mac_key
    mov r12, rdi
    ; seq_num_ptr
    mov r13, rsi
    ; type
    mov r14d, edx
    ; frag
    mov r15, rcx
    ; frag_len
    mov rbp, r8
    ; mac_out
    mov [rsp], r9

    ; Build prefix in mac_header_buf
    lea rdi, [rel mac_header_buf]
    mov rsi, r13
    mov edx, r14d
    mov ecx, ebp
    call _mac_prefix

    ; HMAC-SHA256(mac_key, 32, mac_header_buf || frag, 13 + frag_len, mac_out)
    mov rdi, r12
    mov rsi, 32
    lea rdx, [rel mac_header_buf]
    mov rcx, 13
    add rcx, rbp
    ; mac_out
    mov r8, [rsp]
    call hmac_sha256

    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; ssize_t tls_send(struct tls_ctx *ctx, int fd, int type,
;                   const void *data, uint64_t len)
; rdi = ctx, esi = fd, edx = type, rcx = data, r8 = len
; Returns total bytes written (header + data), or negative on error.
tls_send:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    ; stack: [rsp]=len, [rsp+8]=saved r8
    sub rsp, 16

    ; ctx
    mov r12, rdi
    ; fd
    mov r13d, esi
    ; content type
    mov r14d, edx
    ; data
    mov r15, rcx
    ; save len
    mov [rsp], r8

    cmp r8, TLS_MAX_PAYLOAD
    ja .send_error_too_large

    ; Check if encryption is active (handshake done)
    cmp byte [r12 + tls_ctx.hs_state], HS_DONE
    je .send_encrypted

    ; --- Plaintext send (handshake messages) ---
    lea rsi, [rel header_buf]
    mov [rsi], r14b
    mov word [rsi + 1], (TLS_VERSION_MAJOR << 8) | TLS_VERSION_MINOR
    mov ax, [rsp]
    ror ax, 8
    mov [rsi + 3], ax

    mov edi, r13d
    mov edx, TLS_HEADER_SIZE
    xor ecx, ecx
    call sys_send
    cmp rax, TLS_HEADER_SIZE
    jne .send_error

    mov edi, r13d
    mov rsi, r15
    mov rdx, [rsp]
    xor ecx, ecx
    call sys_send
    cmp rax, [rsp]
    jne .send_error

    add qword [r12 + tls_ctx.write_seq], 1
    mov rax, [rsp]
    add rax, TLS_HEADER_SIZE
    jmp .send_done

.send_encrypted:
    ; --- Encrypted send (after handshake) ---
    ; 1. Compute MAC
    lea rdi, [rel client_write_mac_key]
    lea rsi, [r12 + tls_ctx.write_seq]
    mov edx, r14d
    mov rcx, r15
    ; frag_len
    mov r8, [rsp]
    ; MAC goes after fragment
    lea r9, [record_plaintext + r8]
    call _tls_compute_mac

    ; 2. Build plaintext: fragment + MAC (32 bytes) + padding
    ; Copy fragment to record_plaintext
    mov rsi, r15
    lea rdi, [rel record_plaintext]
    ; frag_len
    mov rcx, [rsp]
    cld
    ; copy fragment
    rep movsb

    ; MAC already at record_plaintext + frag_len (computed above)

    ; Compute total payload length: frag_len + 32 (MAC)
    mov rbx, [rsp]
    ; rbx = payload_base = frag_len + 32
    lea rbx, [rbx + 32]
    ; Add padding: pad to multiple of 16, at least 1 byte
    mov eax, ebx
    xor edx, edx
    mov ecx, 16
    div ecx
    mov ecx, 16
    ; pad_len = 16 - (payload_base % 16)
    sub ecx, edx
    ; ECX is now 1-16 (PKCS#7 always pads)
    ; save payload_base (frag_len + 32)
    mov [rsp + 8], rbx
    ; rbp = total padded plaintext length
    lea rbp, [rbx + rcx]

    ; Write padding bytes (PKCS#7)
    lea rdi, [record_plaintext + r8 + 32]
    ; pad byte value
    movzx ebx, cl
    mov rdx, rcx
.send_pad_loop:
    mov [rdi], bl
    inc rdi
    dec rdx
    jnz .send_pad_loop
    ; rbp already = total padded plaintext length
    ; pad_len
    movzx ecx, bl

    ; 3. Generate random 16-byte explicit IV
    lea rdi, [rel record_iv]
    mov esi, 16
    xor edx, edx
    ; getrandom
    mov eax, 318
    syscall

    ; 4. AES-128-CBC encrypt: ciphertext = AES-CBC(record_iv, plaintext)
    ; Input: key=client_write_key, iv=record_iv, plaintext=record_plaintext
    ; Output: to record_plaintext (in-place)
    lea rdi, [rel client_write_key]
    lea rsi, [rel record_iv]
    lea rdx, [rel record_plaintext]
    ; total plaintext length
    mov rcx, rbp
    lea r8, [rel record_plaintext]
    call aes128_cbc_encrypt

    ; 5. Build TLS record header
    lea rsi, [rel header_buf]
    ; content type
    mov [rsi], r14b
    mov word [rsi + 1], (TLS_VERSION_MAJOR << 8) | TLS_VERSION_MINOR
    ; Record length = 16 (IV) + ciphertext_len (= plaintext_len, same as rbp)
    mov eax, 16
    add eax, ebp
    ror ax, 8
    mov [rsi + 3], ax

    ; Send header
    mov edi, r13d
    mov edx, TLS_HEADER_SIZE
    xor ecx, ecx
    call sys_send
    cmp rax, TLS_HEADER_SIZE
    jne .send_error

    ; Send explicit IV
    mov edi, r13d
    lea rsi, [rel record_iv]
    mov edx, 16
    xor ecx, ecx
    call sys_send
    cmp rax, 16
    jne .send_error

    ; Send ciphertext
    mov edi, r13d
    lea rsi, [rel record_plaintext]
    mov edx, ebp
    xor ecx, ecx
    call sys_send
    cmp rax, rbp
    jne .send_error

    add qword [r12 + tls_ctx.write_seq], 1

    mov eax, TLS_HEADER_SIZE
    add eax, 16
    add eax, ebp
    jmp .send_done

.send_error_too_large:
    mov eax, -2
    jmp .send_done

.send_error:
    or rax, -1

.send_done:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
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
    ; [rsp]=out_len ptr, [rsp+8]=recv_type,
    sub rsp, 24
                                 ; [rsp+16]=saved r8

    ; ctx
    mov rbp, rdi
    ; fd
    mov r13d, esi
    ; out_type
    mov r14, rdx
    ; out_data
    mov r15, rcx
    ; save out_len ptr
    mov [rsp], r8

    ; Read exactly 5 bytes (header)
    lea rbx, [rel header_buf]
    mov edi, r13d
    mov rsi, rbx
    mov edx, TLS_HEADER_SIZE
    call _read_exactly
    test rax, rax
    js .recv_error_read

    ; Parse header
    ; content type
    movzx eax, byte [rbx]
    ; save type
    mov [rsp + 8], al
    ; set out_type
    mov [r14], al

    ; big-endian length
    mov ax, [rbx + 3]
    ror ax, 8
    ; record fragment length
    movzx r12d, ax

    cmp r12d, TLS_MAX_PAYLOAD + 256
    ja .recv_error_bad_length

    ; Check if encryption is active
    cmp byte [rbp + tls_ctx.hs_state], HS_DONE
    je .recv_encrypted

    ; --- Plaintext receive ---
    mov edi, r13d
    mov rsi, r15
    mov edx, r12d
    call _read_exactly
    test rax, rax
    js .recv_error_read

    ; out_len ptr
    mov rax, [rsp]
    mov [rax], r12

    add qword [rbp + tls_ctx.read_seq], 1
    xor eax, eax
    jmp .recv_done

.recv_encrypted:
    ; --- Encrypted receive ---
    ; Fragment = explicit_IV(16) + ciphertext
    ; at least IV + 1 byte
    cmp r12d, 17
    jb .recv_error_bad_length

    ; Read IV + ciphertext into record_plaintext buffer
    mov edi, r13d
    lea rsi, [rel record_plaintext]
    mov edx, r12d
    call _read_exactly
    test rax, rax
    js .recv_error_read

    ; Copy explicit IV from start of record_plaintext
    lea rdi, [rel record_iv]
    lea rsi, [rel record_plaintext]
    mov rcx, 16
    cld
    rep movsb

    ; Decrypt: ciphertext is after IV (offset 16), length = r12d - 16
    mov ecx, r12d
    sub ecx, 16
    ; ciphertext length
    mov r12d, ecx

    ; Decrypt in-place using server_write_key (client receiving from server)
    lea rdi, [rel server_write_key]
    lea rsi, [rel record_iv]
    lea rdx, [rel record_plaintext + 16]
    mov rcx, r12
    lea r8, [rel record_plaintext + 16]
    call aes128_cbc_decrypt

    ; Strip PKCS#7 padding
    lea rsi, [rel record_plaintext + 16]
    add rsi, r12
    dec rsi
    ; last byte = pad value
    movzx eax, byte [rsi]
    cmp eax, 16
    ja .recv_error_decrypt
    test eax, eax
    jz .recv_error_decrypt
    cmp eax, r12d
    ja .recv_error_decrypt

    ; pad_len
    mov ecx, eax
    ; strip padding from length
    sub r12d, ecx

    ; Verify padding bytes (PKCS#7)
    ; save unpadded length
    mov edx, r12d
    ; pad_len
    mov r10d, ecx
.recv_pad_check:
    lea rsi, [rel record_plaintext + 16]
    add rsi, r12
    add rsi, r10
    dec rsi
    movzx ebx, byte [rsi]
    cmp ebx, eax
    jne .recv_error_decrypt
    dec r10d
    jnz .recv_pad_check

    ; Unpadded length = r12d = old_len - pad_len
    ; Now further strip 32-byte MAC
    cmp r12d, 32
    jb .recv_error_decrypt
    sub r12d, 32

    ; Verify MAC
    ; MAC input: seq_num(8) + type(1) + version(2) + fragment_len(2) + fragment
    ; Build MAC prefix in mac_header_buf
    lea rdi, [rel mac_header_buf]
    lea rsi, [rbp + tls_ctx.read_seq]
    ; content type
    mov edx, [rsp + 8]
    ; fragment length (unpadded, without MAC)
    mov ecx, r12d
    call _mac_prefix

    ; Compute expected MAC
    lea rdi, [rel server_write_mac_key]
    mov rsi, 32
    lea rdx, [rel mac_header_buf]
    mov rcx, 13
    add rcx, r12
    ; temporary MAC output
    lea r8, [rel prf_outbuf]
    call hmac_sha256

    ; Compare computed MAC with received MAC
    lea rsi, [rel prf_outbuf]
    lea rdi, [rel record_plaintext + 16]
    add rdi, r12                   ; received MAC starts after fragment
    mov ecx, 32
    cld
    repe cmpsb
    jne .recv_error_decrypt

    ; Copy decrypted fragment to output
    mov rdi, r15
    lea rsi, [rel record_plaintext + 16]
    mov rcx, r12
    cld
    rep movsb

    ; Set out_len
    ; out_len ptr
    mov rax, [rsp]
    mov [rax], r12

    add qword [rbp + tls_ctx.read_seq], 1
    xor eax, eax
    jmp .recv_done

.recv_error_bad_length:
    mov eax, -3
    jmp .recv_done

.recv_error_decrypt:
    or eax, -1
    jmp .recv_done

.recv_error_read:
    or rax, -1

.recv_done:
    add rsp, 24
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
    ; buf
    mov r12, rsi
    ; remaining count
    mov r13, rdx
    ; fd (zero-extend)
    mov edi, edi

.loop:
    mov rsi, r12
    mov rdx, r13
    ; flags = 0 (syscall clobbers rcx)
    xor ecx, ecx
    call sys_recv

    cmp rax, 0
    ; EOF or error
    jle .error

    ; decrease remaining
    sub r13, rax
    ; got everything
    jz .done

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
    sub rsp, 80
    ; rsp+0:  recv_len (8 bytes)
    ; rsp+8:  recv_type (1 byte)
    ; rsp+16: pre_master_secret (48 bytes)

    ; ctx
    mov r12, rdi
    ; fd
    mov r13d, esi

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
    ; out_type
    lea rdx, [rsp + 8]
    ; out_data
    lea rcx, [rel hs_buf]
    ; out_len
    lea r8, [rsp]
    mov rdi, r12
    mov esi, r13d
    call tls_recv
    test eax, eax
    jnz .tcs_error

    ; Must be a Handshake record
    cmp byte [rsp + 8], TLS_HANDSHAKE
    jne .tcs_error

    ; Parse all handshake messages in this fragment thingy
    ; position pointer
    lea r14, [hs_buf]
    ; remaining bytes
    mov r15, [rsp]

.tcs_parse_loop:
    cmp r15, 4
    ; need more data
    jb .tcs_next_recv

    ; Read handshake message header
    ; msg_type
    movzx eax, byte [r14]
    movzx ebx, byte [r14 + 1]
    shl ebx, 16
    movzx ecx, byte [r14 + 2]
    shl ecx, 8
    or ebx, ecx
    movzx ecx, byte [r14 + 3]
    ; ebx = message body length
    or ebx, ecx

    ; Total message size (including 4-byte header)
    lea ecx, [ebx + 4]
    cmp r15, rcx
    ; incomplete message
    jb .tcs_next_recv

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
    ; total current message size
    lea ecx, [ebx + 4]
    sub r15, rcx
    add r14, rcx

    ; Check if handshake complete
    cmp byte [r12 + tls_ctx.hs_state], HS_DONE
    je .tcs_done

    test r15, r15
    ; more messages in this fragment
    jnz .tcs_parse_loop

.tcs_next_recv:
    ; get next TLS record
    jmp .tcs_recv_loop

.tcs_done:
    ; Generate pre_master_secret: 0x0303 + 46 random bytes
    mov word [rsp + 16], 0x0303
    lea rdi, [rsp + 18]
    mov esi, 46
    xor edx, edx
    ; getrandom
    mov eax, 318
    syscall

    mov rdi, r12
    lea rsi, [rsp + 16]
    mov edx, 48
    call tls_derive_keys

    xor eax, eax
    jmp .tcs_return

.tcs_error:
    or eax, -1

.tcs_return:
    add rsp, 80
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
    ; length hi = 0
    mov byte [rsi + 1], 0
    ; length mid = 0
    mov byte [rsi + 2], 0
    ; length lo = 45 (body size)
    mov byte [rsi + 3], 45

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

    ; Cipher suite 1: TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C)
    mov word [rsi + 41], 0x003C
    ; Cipher suite 2: TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003D)
    mov word [rsi + 43], 0x003D

    ; Compression methods length is 1
    mov byte [rsi + 45], 1
    ; Compression method: null (0x00)
    mov byte [rsi + 46], 0

    ; Extensions length is 0
    mov word [rsi + 47], 0

    ; total message length
    mov eax, 49

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
    ; ctx
    mov r10, rdi
    ; body pointer
    mov r11, rsi

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

    ; current offset in body
    mov ecx, 35

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
    ; big-endian → host order
    xchg al, ah
    mov [r10 + tls_ctx.cipher_suite], ax
    ; past cipher suite
    lea ecx, [rcx + 2]

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

    ; secret
    mov r12, rdi
    ; secret_len
    mov r13, rsi
    ; label
    mov r14, rdx
    ; label_len
    mov r15, rcx
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
    ; output pointer
    mov r14, [rsp + 56]
    ; output_len remaining
    mov r15, [rsp + 64]

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
    ; inbuf_len = 32 + seed_buf_len
    lea rcx, [rbp + 32]
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
    ; overwrite A buffer
    lea r8, [rel prf_abuf]
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

; Derive master secret and key block from pre-master secret.
; void tls_derive_keys(struct tls_ctx *ctx,
;                       const void *pre_master_secret, uint64_t pre_master_len)
; rdi = ctx, rsi = pre_master_secret, rdx = pre_master_len
; Result stored in BSS: master_secret, client_write_key, server_write_key,
;                       client_write_iv, server_write_iv
tls_derive_keys:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; ctx
    mov r12, rdi
    ; pre_master_secret
    mov r13, rsi
    ; pre_master_len
    mov r14, rdx

    ; Build seed = client_random + server_random in hs_buf.
    ; Note: must NOT use prf_seed_buf - tls_prf uses it internally
    ; for (label + seed) construction, and if seed pointer overlaps
    ; with prf_seed_buf, the label copy corrupts the source seed.
    lea rdi, [rel hs_buf]
    lea rsi, [r12 + tls_ctx.client_random]
    mov rcx, 32
    cld
    rep movsb

    lea rsi, [r12 + tls_ctx.server_random]
    mov rcx, 32
    rep movsb

    ; PRF(pre_master, "master secret", seed, master_secret, 48)
    mov rdi, r13
    mov rsi, r14
    lea rdx, [rel master_label]
    mov rcx, master_label_len
    lea r8, [rel hs_buf]
    mov r9, 64
    lea rax, [rel master_secret]
    push 48
    push rax
    call tls_prf
    add rsp, 16

    ; Build seed = server_random + client_random in hs_buf
    lea rdi, [rel hs_buf]
    lea rsi, [r12 + tls_ctx.server_random]
    mov rcx, 32
    cld
    rep movsb

    lea rsi, [r12 + tls_ctx.client_random]
    mov rcx, 32
    rep movsb

    ; PRF(master_secret, "key expansion", seed, hs_buf + 64, 96)
    lea rdi, [rel master_secret]
    mov rsi, 48
    lea rdx, [rel key_expansion_label]
    mov rcx, key_expansion_label_len
    lea r8, [rel hs_buf]
    mov r9, 64
    lea rax, [rel hs_buf + 64]
    push 96
    push rax
    call tls_prf
    add rsp, 16

    ; Extract keys from key block at hs_buf + 64
    ; client_write_mac_key (32) + server_write_mac_key (32)
    ; + client_write_key (16) + server_write_key (16)
    lea rsi, [rel hs_buf + 64]
    lea rdi, [rel client_write_mac_key]
    mov rcx, 32
    cld
    rep movsb

    lea rsi, [rel hs_buf + 96]
    lea rdi, [rel server_write_mac_key]
    mov rcx, 32
    rep movsb

    lea rsi, [rel hs_buf + 128]
    lea rdi, [rel client_write_key]
    mov rcx, 16
    rep movsb

    lea rsi, [rel hs_buf + 144]
    lea rdi, [rel server_write_key]
    mov rcx, 16
    rep movsb

    xor eax, eax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
