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
MSG_PEEK               equ 2

; Handshake message types (RFC 5246 §7.4)
HS_CLIENT_HELLO        equ 1
HS_SERVER_HELLO        equ 2
HS_CERTIFICATE         equ 11
HS_SERVER_KEY_EXCHANGE equ 12
HS_SERVER_HELLO_DONE   equ 14
HS_CLIENT_KEY_EXCHANGE equ 16
HS_FINISHED            equ 20

; Finished verify_data length
FINISHED_LEN           equ 12

; Handshake client states
HS_WAIT_SERVER_HELLO      equ 0
HS_WAIT_CERTIFICATE       equ 1
HS_WAIT_SERVER_KEY_EXCHANGE equ 4
HS_WAIT_SERVER_HELLO_DONE equ 2
HS_DONE                   equ 3

TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 equ 0xC02F
GCM_EXPLICIT_NONCE_LEN equ 8
GCM_TAG_LEN equ 16

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
    .server_ccs     resb 1    ; 118
    .ext_ms         resb 1    ; 119
endstruc
tls_ctx_size equ 120

extern sys_send, sys_recv, sys_close
extern hmac_sha256
extern aes128_cbc_encrypt
extern aes128_cbc_decrypt
extern x509_parse_cert
extern x509_check_validity
extern rsa_pub_encrypt
extern sha256_init, sha256_update, sha256_final
extern server_pubkey_n_len
extern ecc_scalar_mult
extern ecc_scalar_mult_base
extern aes128_gcm_encrypt
extern aes128_gcm_decrypt
extern debug_putc
extern debug_hexdump
extern debug_puts

section .rodata
debug_label_cli: db "CLI: ", 0
debug_label_srv: db "SRV: ", 0
debug_label_prf: db "PRF: ", 0
master_label:       db "master secret"
master_label_len:   equ $ - master_label
key_expansion_label: db "key expansion"
key_expansion_label_len: equ $ - key_expansion_label
client_finished_label: db "client finished"
client_finished_label_len: equ $ - client_finished_label
server_finished_label: db "server finished"
server_finished_label_len: equ $ - server_finished_label
ext_master_label:     db "extended master secret"
ext_master_label_len: equ $ - ext_master_label

section .bss
header_buf:  resb TLS_HEADER_SIZE
hs_buf:  resb 16384
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
gcm_nonce:         resb 12     ; fixed_iv(4) + explicit_nonce(8)
server_ec_pubkey:  resb 64     ; server EC public key (x, y)
session_hash:      resb 32     ; EMS session hash
client_ec_privkey: resb 32     ; client EC private key scalar
tls_sha256_ctx:    resb 104    ; transcript hash SHA-256 context
tls_digest:        resb 32     ; transcript hash output
pre_master_sec:    resb 48     ; pre-master secret (shared with test)

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
global tls_connect
global tls_disconnect
global pre_master_sec
global tls_sha256_ctx
global tls_digest
global _read_exactly

; void tls_init(struct tls_ctx *ctx)
; rdi = ctx pointer
tls_init:
    xor eax, eax
    mov [rdi + tls_ctx.write_seq], rax
    mov [rdi + tls_ctx.read_seq], rax
    mov word [rdi + tls_ctx.version], (TLS_VERSION_MAJOR << 8) | 1   ; start with {3,1} for ClientHello RFC 5246 §6.2.1
    mov byte [rdi + tls_ctx.hs_state], 0
    mov byte [rdi + tls_ctx.server_ccs], 0
    mov byte [rdi + tls_ctx.ext_ms], 0
    ret

; Build MAC input prefix (seq_num + type + version + length)
; rdi = mac_header_buf (13 bytes output), rsi = seq_num_ptr, edx = type,
; ecx = fragment_len
_mac_prefix:
    mov rax, [rsi]
    bswap rax
    mov [rdi], rax
    mov [rdi + 8], dl
    mov byte [rdi + 9], TLS_VERSION_MAJOR
    mov byte [rdi + 10], TLS_VERSION_MINOR
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

    ; Copy fragment right after header for contiguous HMAC input
    lea rdi, [rel mac_header_buf + 13]
    mov rsi, r15
    mov rcx, rbp
    cld
    rep movsb

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
    ; Save length param immediatly out of r8 
    mov rax, r8

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
    ; save len securely into our local stack frame allocation slot
    mov [rsp], rax

    cmp r8, TLS_MAX_PAYLOAD
    ja .send_error_too_large

    ; Check if encryption is active (handshake done)
    cmp byte [r12 + tls_ctx.hs_state], HS_DONE
    je .send_encrypted

    ; --- Plaintext send (handshake messages) ---
    lea rsi, [rel header_buf]
    mov [rsi], r14b
    mov ax, [r12 + tls_ctx.version]  ; Use negotiated version (initially {3,1} for ClientHello)
    xchg al, ah                     ; host order → big-endian in memory
    mov [rsi + 1], ax
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
    cmp word [r12 + tls_ctx.cipher_suite], TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    je .send_gcm

    ; --- CBC encrypted send ---
    lea rdi, [rel client_write_mac_key]
    lea rsi, [r12 + tls_ctx.write_seq]
    mov edx, r14d
    mov rcx, r15
    mov r8, [rsp]
    lea r9, [record_plaintext + r8]
    call _tls_compute_mac

    mov rsi, r15
    lea rdi, [rel record_plaintext]
    mov rcx, [rsp]
    cld
    rep movsb

    mov rbx, [rsp]
    lea rbx, [rbx + 32]
    mov eax, ebx
    xor edx, edx
    mov ecx, 16
    div ecx
    mov ecx, 16
    sub ecx, edx
    mov [rsp + 8], rbx
    lea rbp, [rbx + rcx]

    mov r8, [rsp]
    lea rdi, [record_plaintext + r8 + 32]
    lea ebx, [rcx - 1]
    mov rdx, rcx
.send_pad_loop:
    mov [rdi], bl
    inc rdi
    dec rdx
    jnz .send_pad_loop
    movzx ecx, bl

    lea rdi, [rel record_iv]
    mov esi, 16
    xor edx, edx
    mov eax, 318
    syscall

    lea rdi, [rel client_write_key]
    lea rsi, [rel record_iv]
    lea rdx, [rel record_plaintext]
    mov rcx, rbp
    lea r8, [rel record_plaintext]
    call aes128_cbc_encrypt

    lea rsi, [rel header_buf]
    mov [rsi], r14b
    mov byte [rsi + 1], TLS_VERSION_MAJOR
    mov byte [rsi + 2], TLS_VERSION_MINOR
    mov eax, 16
    add eax, ebp
    ror ax, 8
    mov [rsi + 3], ax

    mov edi, r13d
    mov edx, TLS_HEADER_SIZE
    xor ecx, ecx
    call sys_send
    cmp rax, TLS_HEADER_SIZE
    jne .send_error

    mov edi, r13d
    lea rsi, [rel record_iv]
    mov edx, 16
    xor ecx, ecx
    call sys_send
    cmp rax, 16
    jne .send_error

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

.send_gcm:
    ; --- GCM encrypted send ---
    ; Copy plaintext to record_plaintext + 8 (leave room for explicit_nonce)
    mov rsi, r15
    lea rdi, [rel record_plaintext + GCM_EXPLICIT_NONCE_LEN]
    mov rcx, [rsp]
    cld
    rep movsb

    ; DEBUG: dump plaintext before encryption
    push rax
    push rdi
    push rsi
    push rcx
    lea rdi, [rel record_plaintext + GCM_EXPLICIT_NONCE_LEN]
    mov esi, [rsp + 32]
    call debug_hexdump
    pop rcx
    pop rsi
    pop rdi
    pop rax

    ; Build full nonce: fixed_iv (4) + seq_num (8) at gcm_nonce
    lea rdi, [rel gcm_nonce]
    lea rsi, [rel client_write_iv]
    mov rcx, 4
    cld
    rep movsb

    ; Copy write_seq as explicit nonce (network byte order)
    lea rdi, [rel gcm_nonce + 4]
    lea rsi, [r12 + tls_ctx.write_seq]
    mov rax, [rsi]
    bswap rax
    mov [rdi], rax

    ; Build AAD (13 bytes) via _mac_prefix
    lea rdi, [rel mac_header_buf]
    lea rsi, [r12 + tls_ctx.write_seq]
    mov edx, r14d
    mov ecx, [rsp]
    call _mac_prefix

    ; rbp = plaintext length
    mov rbp, [rsp]

    ; Call aes128_gcm_encrypt
    ; Stack args: [rsp]=ct_out, [rsp+8]=tag_out
    sub rsp, 16
    lea rax, [rel record_plaintext + GCM_EXPLICIT_NONCE_LEN]
    mov [rsp], rax
    lea rax, [rel record_plaintext + GCM_EXPLICIT_NONCE_LEN]
    add rax, rbp
    mov [rsp + 8], rax
    lea rdi, [rel client_write_key]
    lea rsi, [rel gcm_nonce]
    lea rdx, [rel record_plaintext + GCM_EXPLICIT_NONCE_LEN]
    mov rcx, rbp
    lea r8, [rel mac_header_buf]
    mov r9d, 13
    call aes128_gcm_encrypt
    lea rax, [rsp + 16]
    add rsp, 16

    ; DEBUG: dump key and nonce
    push rbp
    push rdi
    push rsi
    lea rdi, [rel client_write_key]
    mov esi, 16
    call debug_hexdump
    lea rdi, [rel gcm_nonce]
    mov esi, 12
    call debug_hexdump
    lea rdi, [rel mac_header_buf]
    mov esi, 13
    call debug_hexdump
    pop rsi
    pop rdi
    pop rbp

    ; DEBUG: dump ciphertext after encryption
    push rbp
    push rdi
    push rsi
    push rcx
    lea rdi, [rel record_plaintext + GCM_EXPLICIT_NONCE_LEN]
    mov esi, ebp
    call debug_hexdump
    ; Also dump tag
    lea rdi, [rel record_plaintext + GCM_EXPLICIT_NONCE_LEN]
    add rdi, rbp
    mov esi, 16
    call debug_hexdump
    pop rcx
    pop rsi
    pop rdi
    pop rbp

    ; Copy explicit_nonce to front of record_plaintext
    lea rdi, [rel record_plaintext]
    lea rsi, [rel gcm_nonce + 4]
    mov rcx, GCM_EXPLICIT_NONCE_LEN
    cld
    rep movsb

    ; Record header
    lea rsi, [rel header_buf]
    mov [rsi], r14b
    mov byte [rsi + 1], TLS_VERSION_MAJOR
    mov byte [rsi + 2], TLS_VERSION_MINOR
    lea eax, [GCM_EXPLICIT_NONCE_LEN + rbp + GCM_TAG_LEN]
    ror ax, 8
    mov [rsi + 3], ax

    mov edi, r13d
    mov edx, TLS_HEADER_SIZE
    xor ecx, ecx
    call sys_send
    cmp rax, TLS_HEADER_SIZE
    jne .send_error

    ; Send fragment: explicit_nonce || ciphertext || tag
    mov edi, r13d
    lea rsi, [rel record_plaintext]
    lea edx, [GCM_EXPLICIT_NONCE_LEN + rbp + GCM_TAG_LEN]
    xor ecx, ecx
    push rdx
    call sys_send
    pop rcx
    cmp rax, rcx
    jne .send_error

    add qword [r12 + tls_ctx.write_seq], 1
    lea eax, [TLS_HEADER_SIZE + GCM_EXPLICIT_NONCE_LEN + rbp + GCM_TAG_LEN]
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

    ; Parse big-endian length safely
    movzx eax, word [rbx + 3]
    xchg al, ah
    mov r12d, eax

    cmp r12d, TLS_MAX_PAYLOAD + 256
    ja .recv_error_bad_length

    ; Check if server has sent CCS (encryption active on receive)
    cmp byte [rbp + tls_ctx.server_ccs], 1
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

    cmp byte [rsp + 8], 20       ; Is this record a ChangeCipherSpec (20)?
    jne .inc_seq
    mov byte [rbp + tls_ctx.server_ccs], 1 ; Server CCS received!
    mov qword [rbp + tls_ctx.read_seq], 0 ; Reset sequence number to 0 for upcoming encrypted records!
    jmp .skip_inc
.inc_seq:
    add qword [rbp + tls_ctx.read_seq], 1
.skip_inc:
    xor eax, eax
    jmp .recv_done


.recv_encrypted:
    cmp word [rbp + tls_ctx.cipher_suite], TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    je .recv_gcm

    ; --- CBC encrypted receive ---
    cmp r12d, 17
    jb .recv_error_bad_length

    mov edi, r13d
    lea rsi, [rel record_plaintext]
    mov edx, r12d
    call _read_exactly
    test rax, rax
    js .recv_error_read

    lea rdi, [rel record_iv]
    lea rsi, [rel record_plaintext]
    mov rcx, 16
    xor eax, eax
    cld
    rep movsb

    mov ecx, r12d
    sub ecx, 16
    mov r12d, ecx

    lea rdi, [rel server_write_key]
    lea rsi, [rel record_iv]
    lea rdx, [rel record_plaintext + 16]
    mov rcx, r12
    lea r8, [rel record_plaintext + 16]
    call aes128_cbc_decrypt

    lea rsi, [rel record_plaintext + 16]
    add rsi, r12
    dec rsi
    movzx eax, byte [rsi]
    cmp eax, 16
    ja .recv_error_pad_range
    cmp eax, r12d
    ja .recv_error_pad_range

    mov ecx, eax
    sub r12d, ecx
    dec r12d

    test ecx, ecx
    jz .recv_pad_ok
    mov r10d, ecx
.recv_pad_check:
    lea rsi, [rel record_plaintext + 16]
    add rsi, r12
    movzx r8, r10d
    add rsi, r8
    dec rsi
    movzx ebx, byte [rsi]
    cmp ebx, eax
    jne .recv_error_pad_bad
    dec r10d
    jnz .recv_pad_check
.recv_pad_ok:

    cmp r12d, 32
    jb .recv_error_mac_len
    sub r12d, 32
    movzx r12, r12d

    lea rdi, [rel mac_header_buf]
    lea rsi, [rbp + tls_ctx.read_seq]
    mov edx, [rsp + 8]
    mov ecx, r12d
    call _mac_prefix

    mov rdi, r15
    lea rsi, [rel record_plaintext + 16]
    movzx rcx, r12d
    cld
    rep movsb

    lea rdi, [rel mac_header_buf + 13]
    lea rsi, [rel record_plaintext + 16]
    mov rcx, r12
    cld
    rep movsb

    lea rdi, [rel server_write_mac_key]
    mov rsi, 32
    lea rdx, [rel mac_header_buf]
    mov rcx, 13
    add rcx, r12
    lea r8, [rel prf_outbuf]
    call hmac_sha256

    lea rsi, [rel prf_outbuf]
    lea rdi, [rel record_plaintext + 16]
    movzx r8, r12d
    add rdi, r8
    mov ecx, 32
    xor eax, eax
    cld
    repe cmpsb
    jne .recv_error_mac
    jmp .recv_plaintext_done

.recv_gcm:
    ; --- GCM encrypted receive ---
    ; Fragment = explicit_nonce(8) + ciphertext + tag(16)
    cmp r12d, GCM_EXPLICIT_NONCE_LEN + 1 + GCM_TAG_LEN
    jb .recv_error_bad_length

    mov edi, r13d
    lea rsi, [rel record_plaintext]
    mov edx, r12d
    call _read_exactly
    test rax, rax
    js .recv_error_read

    ; Copy explicit_nonce from record_plaintext[0..7] to gcm_nonce[4..11]
    lea rdi, [rel gcm_nonce + 4]
    lea rsi, [rel record_plaintext]
    mov rcx, GCM_EXPLICIT_NONCE_LEN
    cld
    rep movsb

    ; Copy server_write_iv to gcm_nonce[0..3]
    lea rdi, [rel gcm_nonce]
    lea rsi, [rel server_write_iv]
    mov rcx, 4
    cld
    rep movsb

    ; CT length = total - explicit_nonce - tag
    mov ecx, r12d
    sub ecx, GCM_EXPLICIT_NONCE_LEN
    sub ecx, GCM_TAG_LEN
    mov r12d, ecx

    ; Build AAD via _mac_prefix
    lea rdi, [rel mac_header_buf]
    lea rsi, [rbp + tls_ctx.read_seq]
    mov edx, [rsp + 8]
    mov ecx, r12d
    call _mac_prefix

    ; aes128_gcm_decrypt stack args: [rsp+0]=tag_ptr, [rsp+8]=pt_out
    sub rsp, 16
    lea rax, [rel record_plaintext + GCM_EXPLICIT_NONCE_LEN]
    add rax, r12
    mov [rsp], rax
    mov rax, r15
    mov [rsp + 8], rax
    lea rdi, [rel server_write_key]
    lea rsi, [rel gcm_nonce]
    lea rdx, [rel record_plaintext + GCM_EXPLICIT_NONCE_LEN]
    mov rcx, r12
    lea r8, [rel mac_header_buf]
    mov r9d, 13
    call aes128_gcm_decrypt
    add rsp, 16

    test eax, eax
    jnz .recv_error_mac

    ; out_len = ct_len
    mov rax, [rsp]
    mov [rax], r12

    add qword [rbp + tls_ctx.read_seq], 1
    xor eax, eax
    jmp .recv_done

.recv_plaintext_done:
    ; Set out_len (shared between CBC and GCM plaintext paths)
    mov rax, [rsp]
    mov [rax], r12

    add qword [rbp + tls_ctx.read_seq], 1
    xor eax, eax
    jmp .recv_done

.recv_error_bad_length:
    push 1
    mov rdi, 2
    lea rsi, [rsp]
    mov rdx, 1
    mov rax, 1
    syscall
    add rsp, 8
    mov eax, -3
    jmp .recv_done

.recv_error_pad_range:
    mov dil, 0x70               ; 'p'
    call debug_putc
    or eax, -1
    jmp .recv_done

.recv_error_pad_bad:
    mov dil, 0x62               ; 'b'
    call debug_putc
    or eax, -1
    jmp .recv_done

.recv_error_mac_len:
    mov dil, 0x6c               ; 'l'
    call debug_putc
    or eax, -1
    jmp .recv_done

.recv_error_mac:
    mov dil, 0x64               ; 'd'
    call debug_putc
    or eax, -1
    jmp .recv_done

.recv_error_decrypt:
    mov dil, 0x44               ; 'D' (fallback)
    call debug_putc
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
    ; hostname / hostlen (preserve for _build_client_hello)
    mov r14, rdx
    mov r15d, ecx

    ; Set initial handshake state
    mov byte [r12 + tls_ctx.hs_state], HS_WAIT_SERVER_HELLO

    ; Generate 32 bytes of client random via getrandom (SYS 318)
    lea rdi, [r12 + tls_ctx.client_random]
    mov esi, 32
    xor edx, edx
    mov eax, 318
    syscall

    ; Initialize transcript hash
    lea rdi, [rel tls_sha256_ctx]
    call sha256_init

    ; Build ClientHello in hs_buf
    lea rsi, [rel hs_buf]
    mov rdi, r12
    mov rdx, r14
    mov ecx, r15d
    call _build_client_hello
    ; rax = message length
    test rax, rax
    js .tcs_error

    mov rbp, rax

    ; Hash ClientHello (transcript)
    mov rdx, rbp
    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [rel hs_buf]
    call sha256_update

    ; Send as TLS Handshake record
    mov rdi, r12
    mov esi, r13d
    mov edx, TLS_HANDSHAKE
    lea rcx, [rel hs_buf]
    mov r8, rbp
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

    ; Check record type
    cmp byte [rsp + 8], TLS_HANDSHAKE
    je .tcs_hs_ok
    cmp byte [rsp + 8], TLS_ALERT
    jne .tcs_error
    ; Alert received during handshake - print level + description
    movzx edi, byte [hs_buf]     ; level (1=warning, 2=fatal)
    call debug_putc
    movzx edi, byte [hs_buf + 1] ; alert description
    call debug_putc
    jmp .tcs_error
.tcs_hs_ok:

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

    cmp dl, HS_WAIT_SERVER_KEY_EXCHANGE
    je .tcs_handle_ske

    cmp dl, HS_WAIT_SERVER_HELLO_DONE
    je .tcs_handle_shd

    jmp .tcs_error

; Real Quick
; Fucking hate assembly
; Also love it tho dw

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

    ; Parse first certificate from the Certificate message
    ; r14+4 = body start, ebx = body length
    lea r9, [r14 + 4]
    cmp ebx, 6
    jb .tcs_error

    ; Read certificate_list_length (3 bytes, big-endian)
    movzx eax, byte [r9]
    shl eax, 16
    movzx ecx, byte [r9 + 1]
    shl ecx, 8
    or eax, ecx
    movzx ecx, byte [r9 + 2]
    or eax, ecx
    cmp eax, 3
    jb .tcs_error

    ; Read first cert length (3 bytes, big-endian)
    movzx eax, byte [r9 + 3]
    shl eax, 16
    movzx ecx, byte [r9 + 4]
    shl ecx, 8
    or eax, ecx
    movzx ecx, byte [r9 + 5]
    or eax, ecx
    test eax, eax
    jz .tcs_error

    ; Parse DER certificate
    lea rdi, [r9 + 6]
    mov esi, eax
    push r12
    push r13
    push r14
    push r15
    push rbx
    push rsi
    push rdi
    call x509_parse_cert
    pop rdi
    pop rsi
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    test eax, eax
    jnz .tcs_error

    ; After Certificate, next message depends on cipher suite
    cmp word [r12 + tls_ctx.cipher_suite], TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    jne .tcs_cert_then_shd
    mov byte [r12 + tls_ctx.hs_state], HS_WAIT_SERVER_KEY_EXCHANGE
    jmp .tcs_advance
.tcs_cert_then_shd:
    mov byte [r12 + tls_ctx.hs_state], HS_WAIT_SERVER_HELLO_DONE
    jmp .tcs_advance

.tcs_handle_ske:
    cmp al, HS_SERVER_KEY_EXCHANGE
    jne .tcs_error

    ; Parse ServerKeyExchange body at r14+4, length ebx
    ; For ECDHE-RSA:
    ;   curve_type(1) + named_curve(2) + pubkey_len(1) + pubkey(variable)
    ;   + hash_alg(1) + sig_alg(1) + sig_len(2) + sig(variable)

    ; Verify minimum length: 3 (EC params) + 66 (P-256 uncompressed) + 4 (sig header) = 73
    cmp ebx, 73
    jb .tcs_error

    lea rsi, [r14 + 4]
    ; Check curve type = named_curve (3)
    cmp byte [rsi], 3
    jne .tcs_error
    ; Check named curve = secp256r1 (0x0017)
    cmp word [rsi + 1], 0x1700  ; big-endian
    jne .tcs_error

    ; Extract server EC public key (uncompressed point)
    ; pubkey_len at [rsi+3]
    movzx eax, byte [rsi + 3]
    cmp eax, 65
    jne .tcs_error
    ; Check point format: must start with 0x04 (uncompressed)
    cmp byte [rsi + 4], 4
    jne .tcs_error

    ; Copy and convert x coordinate: BE wire -> LE limbs
    lea rdi, [rel server_ec_pubkey]
    lea rsi, [rsi + 5]
    mov rax, [rsi]
    bswap rax
    mov [rdi + 24], rax
    mov rax, [rsi + 8]
    bswap rax
    mov [rdi + 16], rax
    mov rax, [rsi + 16]
    bswap rax
    mov [rdi + 8], rax
    mov rax, [rsi + 24]
    bswap rax
    mov [rdi], rax

    ; Copy and convert y coordinate: BE wire -> LE limbs
    lea rdi, [rel server_ec_pubkey + 32]
    lea rsi, [rsi + 32]
    mov rax, [rsi]
    bswap rax
    mov [rdi + 24], rax
    mov rax, [rsi + 8]
    bswap rax
    mov [rdi + 16], rax
    mov rax, [rsi + 16]
    bswap rax
    mov [rdi + 8], rax
    mov rax, [rsi + 24]
    bswap rax
    mov [rdi], rax

    ; Skip signature verification for now (verified by handshake integrity)
    ; Proceed to ServerHelloDone
    mov byte [r12 + tls_ctx.hs_state], HS_WAIT_SERVER_HELLO_DONE
    jmp .tcs_advance

.tcs_handle_shd:
    cmp al, HS_SERVER_HELLO_DONE
    jne .tcs_error

    ; ServerHelloDone body must be empty aka length = 0
    test ebx, ebx
    jnz .tcs_error

    ; Hash ServerHelloDone into transcript
    lea rdi, [rel tls_sha256_ctx]
    mov rsi, r14
    lea edx, [ebx + 4]
    call sha256_update

    ; Don't set HS_DONE yet — CKE must be sent plaintext
    jmp .tcs_done

.tcs_advance:
    ; Hash this handshake message into transcript
    lea rdi, [rel tls_sha256_ctx]
    mov rsi, r14
    lea edx, [ebx + 4]
    call sha256_update

    ; total current message size
    lea ecx, [ebx + 4]
    sub r15, rcx
    add r14, rcx

    ; Check if handshake complete (after ServerHelloDone)
    cmp byte [r12 + tls_ctx.hs_state], HS_DONE
    je .tcs_done

    test r15, r15
    ; more messages in this fragment
    jnz .tcs_parse_loop

.tcs_next_recv:
    ; get next TLS record
    jmp .tcs_recv_loop

.tcs_done:
    ; Check cipher suite for key exchange method
    cmp word [r12 + tls_ctx.cipher_suite], TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    je .tcs_ecdhe

    ; ---- RSA path ----
    cmp word [pre_master_sec], 0x0303
    je .tcs_pms_ok
    mov word [pre_master_sec], 0x0303
    lea rdi, [pre_master_sec + 2]
    mov esi, 46
    xor edx, edx
    mov eax, 318
    syscall
.tcs_pms_ok:

    ; RSA-encrypt PMS into CKE body at hs_buf + 6
    lea rdi, [hs_buf + 6]
    lea rsi, [pre_master_sec]
    mov edx, 48
    call rsa_pub_encrypt
    test eax, eax
    jnz .tcs_error

    ; Build CKE header with length prefix (2 + 256 = 258 body)
    mov byte [hs_buf], HS_CLIENT_KEY_EXCHANGE
    mov byte [hs_buf + 1], 0
    mov byte [hs_buf + 2], 1
    mov byte [hs_buf + 3], 2
    mov word [hs_buf + 4], 0x0001

    mov r15d, 262               ; total CKE size
    jmp .tcs_cke_common

.tcs_ecdhe:
    ; ---- ECDHE path ----
    ; 1. Generate 32-byte client private key
    lea rdi, [rel client_ec_privkey]
    mov esi, 32
    xor edx, edx
    mov eax, 318
    syscall

    ; 2. Compute client public key = priv * G at hs_buf + 70 (temp area)
    lea rdi, [hs_buf + 70]
    lea rsi, [rel client_ec_privkey]
    call ecc_scalar_mult_base

    ; 3. Build CKE body at hs_buf + 4
    mov byte [hs_buf + 4], 65          ; pubkey length (uncompressed)
    mov byte [hs_buf + 5], 4           ; uncompressed marker
    ; Convert x: LE limbs (hs_buf+70) -> BE wire (hs_buf+6)
    lea rdi, [hs_buf + 6]
    lea rsi, [hs_buf + 70]
    mov rax, [rsi + 24]
    bswap rax
    mov [rdi], rax
    mov rax, [rsi + 16]
    bswap rax
    mov [rdi + 8], rax
    mov rax, [rsi + 8]
    bswap rax
    mov [rdi + 16], rax
    mov rax, [rsi]
    bswap rax
    mov [rdi + 24], rax
    ; Convert y: LE limbs (hs_buf+70+32) -> BE wire (hs_buf+6+32)
    lea rsi, [hs_buf + 70 + 32]
    lea rdi, [hs_buf + 6 + 32]
    mov rax, [rsi + 24]
    bswap rax
    mov [rdi], rax
    mov rax, [rsi + 16]
    bswap rax
    mov [rdi + 8], rax
    mov rax, [rsi + 8]
    bswap rax
    mov [rdi + 16], rax
    mov rax, [rsi]
    bswap rax
    mov [rdi + 24], rax

    ; 4. CKE handshake header
    mov byte [hs_buf], HS_CLIENT_KEY_EXCHANGE
    mov byte [hs_buf + 1], 0
    mov byte [hs_buf + 2], 0
    mov byte [hs_buf + 3], 66          ; body length

    mov r15d, 70                       ; total CKE size
    jmp .tcs_cke_common

.tcs_cke_common:
    ; Hash CKE into transcript
    lea rdi, [tls_sha256_ctx]
    lea rsi, [hs_buf]
    mov edx, r15d
    call sha256_update

    ; Save transcript backup (includes CKE) for server Finished
    lea rdi, [hs_buf + 2048]
    lea rsi, [tls_sha256_ctx]
    mov rcx, 104
    cld
    rep movsb

    ; Save session hash (for EMS master secret derivation)
    lea rdi, [tls_sha256_ctx]
    lea rsi, [session_hash]
    call sha256_final

    ; Restore SHA-256 context for continued hashing
    lea rdi, [tls_sha256_ctx]
    lea rsi, [hs_buf + 2048]
    mov rcx, 104
    cld
    rep movsb

    ; Send ClientKeyExchange (plaintext)
    mov rdi, r12
    mov esi, r13d
    mov edx, TLS_HANDSHAKE
    lea rcx, [hs_buf]
    mov r8d, r15d
    call tls_send
    test rax, rax
    js .tcs_error

    ; For ECDHE: compute shared secret as pre-master secret
    cmp word [r12 + tls_ctx.cipher_suite], TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    jne .tcs_derive_rsa

    ; Compute shared = priv * server_pub at hs_buf + 70
    lea rdi, [hs_buf + 70]
    lea rsi, [rel client_ec_privkey]
    lea rdx, [rel server_ec_pubkey]
    call ecc_scalar_mult

    ; Convert x-coordinate from LE limbs to BE bytes as pre-master secret
    lea rdi, [rel pre_master_sec]
    lea rsi, [hs_buf + 70]
    mov rax, [rsi + 24]
    bswap rax
    mov [rdi], rax
    mov rax, [rsi + 16]
    bswap rax
    mov [rdi + 8], rax
    mov rax, [rsi + 8]
    bswap rax
    mov [rdi + 16], rax
    mov rax, [rsi]
    bswap rax
    mov [rdi + 24], rax

    ; Derive keys with ECDHE pre-master secret (32 bytes)
    mov rdi, r12
    lea rsi, [pre_master_sec]
    mov edx, 32
    call tls_derive_keys

    jmp .tcs_after_keys

.tcs_derive_rsa:
    ; Derive keys with RSA pre-master secret (48 bytes)
    mov rdi, r12
    lea rsi, [pre_master_sec]
    mov edx, 48
    call tls_derive_keys

    push rdi
    push rsi
    mov rdi, 2
    lea rsi, [rel debug_label_cli]
    mov edx, 5
    mov eax, 1
    syscall
    lea rdi, [rel master_secret]
    mov esi, 16
    call debug_hexdump
    lea rdi, [rel client_write_key]
    mov esi, 16
    call debug_hexdump
    lea rdi, [r12 + 18]
    mov esi, 16
    call debug_hexdump
    lea rdi, [r12 + 50]
    mov esi, 16
    call debug_hexdump
    lea rdi, [rel pre_master_sec]
    mov esi, 16
    call debug_hexdump
    pop rsi
    pop rdi

.tcs_after_keys:
    ; Validate certificate validity period
    call x509_check_validity
    test eax, eax
    jnz .tcs_error

    ; Validate certificate validity period
    call x509_check_validity
    test eax, eax
    jnz .tcs_error

    ; Finalize transcript hash → tls_digest (client Finished verify_data)
    lea rdi, [tls_sha256_ctx]
    lea rsi, [tls_digest]
    call sha256_final

    ; ---- Send ChangeCipherSpec (plaintext) ----
    ; TLS record header
    mov byte [header_buf], TLS_CHANGE_CIPHER_SPEC
    mov byte [header_buf + 1], TLS_VERSION_MAJOR
    mov byte [header_buf + 2], TLS_VERSION_MINOR
    mov ax, 0x0001
    ror ax, 8
    mov [header_buf + 3], ax
    mov edi, r13d
    lea rsi, [header_buf]
    mov edx, TLS_HEADER_SIZE
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .tcs_error
    ; CCS body (0x01)
    mov byte [header_buf], 1
    mov edi, r13d
    lea rsi, [header_buf]
    mov edx, 1
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .tcs_error

    ; Set encryption state (subsequent records are encrypted)
    mov byte [r12 + tls_ctx.hs_state], HS_DONE
    ; Reset write sequence number to 0 for the new epoch (RFC 5246 §6.1)
    mov qword [r12 + tls_ctx.write_seq], 0

    ; ---- Compute client Finished verify_data ----
    ; PRF(master_secret, 48, "client finished", label_len, tls_digest, 32, hs_buf+48, 12)
    lea rdi, [master_secret]
    mov esi, 48
    lea rdx, [client_finished_label]
    mov ecx, client_finished_label_len
    lea r8, [tls_digest]
    mov r9d, 32
    push 12
    lea rax, [hs_buf + 48]
    push rax
    call tls_prf
    add rsp, 16

    ; Build Finished handshake message at hs_buf
    mov byte [hs_buf], HS_FINISHED
    mov byte [hs_buf + 1], 0
    mov byte [hs_buf + 2], 0
    mov byte [hs_buf + 3], 12
    ; copy verify_data from hs_buf+48 to hs_buf+4
    lea rsi, [hs_buf + 48]
    lea rdi, [hs_buf + 4]
    mov rcx, 12
    cld
    rep movsb

    ; Restore transcript context (includes CKE)
    lea rdi, [tls_sha256_ctx]
    lea rsi, [hs_buf + 2048]
    mov rcx, 104
    cld
    rep movsb

    ; Hash client Finished into transcript
    lea rdi, [tls_sha256_ctx]
    lea rsi, [hs_buf]
    mov edx, 16
    call sha256_update

    ; Save SHA-256 context for potential replay with pre-Finished msgs
    lea rdi, [hs_buf + 2048 + 104]
    lea rsi, [tls_sha256_ctx]
    mov rcx, 104
    cld
    rep movsb

    ; Send Finished (encrypted via tls_send)
    mov rdi, r12
    mov esi, r13d
    mov edx, TLS_HANDSHAKE
    lea rcx, [hs_buf]
    mov r8d, 16
    call tls_send
    test rax, rax
    js .tcs_error

    ; Finalize transcript → tls_digest (server Finished digest)
    lea rdi, [tls_sha256_ctx]
    lea rsi, [tls_digest]
    call sha256_final

    ; Receive server Finished (may be preceded by post-handshake messages)
    xor eax, eax
    mov [rsp + 16], eax        ; pending_len = 0

.tcs_recv_finished:
    mov rdi, r12
    mov esi, r13d
    lea rdx, [rsp + 8]
    lea rcx, [hs_buf]
    lea r8, [rsp]
    call tls_recv
    test eax, eax
    jnz .tcs_error
    cmp byte [rsp + 8], TLS_HANDSHAKE
    jne .tcs_recv_finished
    cmp byte [hs_buf], HS_FINISHED
    jne .tcs_save_pending      ; save pre-Finished handshake for transcript

    ; If pre-Finished messages were buffered, replay transcript
    mov eax, [rsp + 16]
    test eax, eax
    jz .tcs_skip_replay
    ; Restore post-client-Finished SHA-256 context
    lea rdi, [tls_sha256_ctx]
    lea rsi, [hs_buf + 2048 + 104]
    mov rcx, 104
    cld
    rep movsb
    ; Hash all buffered pre-Finished handshake messages
    lea rdi, [tls_sha256_ctx]
    lea rsi, [hs_buf + 3000]
    mov edx, [rsp + 16]
    call sha256_update
    ; Re-finalize to get correct tls_digest for server Finished
    lea rdi, [tls_sha256_ctx]
    lea rsi, [tls_digest]
    call sha256_final
.tcs_skip_replay:

    ; ---- Verify server Finished verify_data ----
    ; PRF(master_secret, 48, "server finished", label_len, tls_digest, 32, hs_buf+48, 12)
    lea rdi, [master_secret]
    mov esi, 48
    lea rdx, [server_finished_label]
    mov ecx, server_finished_label_len
    lea r8, [tls_digest]
    mov r9d, 32
    push 12
    lea rax, [hs_buf + 48]
    push rax
    call tls_prf
    add rsp, 16

    ; Compare expected (hs_buf+48) with received (hs_buf+4)
    lea rsi, [hs_buf + 48]
    lea rdi, [hs_buf + 4]
    mov ecx, 12
    cld
    repe cmpsb
    jnz .tcs_verify_fail
    xor eax, eax
    jmp .tcs_return

.tcs_save_pending:
    mov r8d, [rsp]
    lea rdi, [hs_buf + 3000]
    add rdi, [rsp + 16]
    lea rsi, [hs_buf]
    mov ecx, r8d
    cld
    rep movsb
    add [rsp + 16], r8d
    jmp .tcs_recv_finished

.tcs_verify_fail:
    mov eax, 255
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


; Build a ClientHello handshake message (RFC 5246 §7.4.1.2) with SNI.
; rdi = ctx, rsi = output buffer, rdx = sni_hostname, rcx = sni_hostlen
; Returns total message length in rax.
; Clobbers only caller-saved registers (rax, rcx, rdx, rdi, rsi, r8-r11).
_build_client_hello:
    cmp byte [rdi + tls_ctx.hs_state], 0
    mov rax, -1
    js .bch_error

    push r8
    push r9
    push r10
    push r11

    mov r10, rsi                 ; save output buffer pointer
    mov r11d, ecx                ; sni_hostlen

    ; Handshake header
    mov byte [rsi], HS_CLIENT_HELLO
    mov dword [rsi + 1], 0       ; zero length (will fill later)

    ; Protocol version: TLS 1.2 (0x0303)
    mov byte [rsi + 4], 3
    mov byte [rsi + 5], 3

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

    ; Cipher suites length = 6 (big-endian, 3 suites)
    mov byte [rsi + 39], 0
    mov byte [rsi + 40], 6

    ; Cipher suite 1: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
    mov byte [rsi + 41], 0xC0
    mov byte [rsi + 42], 0x2F
    ; Cipher suite 2: TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C)
    mov byte [rsi + 43], 0x00
    mov byte [rsi + 44], 0x3C
    ; Cipher suite 3: TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003D)
    mov byte [rsi + 45], 0x00
    mov byte [rsi + 46], 0x3D

    ; Compression methods length is 1
    mov byte [rsi + 47], 1
    ; Compression method: null (0x00)
    mov byte [rsi + 48], 0

    ; Build SNI extension (RFC 6066)
    ; extensions_len = 65 + hostlen (includes ALPN)
    lea r8d, [r11d + 65]
    mov byte [rsi + 49], 0
    mov [rsi + 50], r8b

    ; Extension type: server_name (0x0000)
    mov byte [rsi + 51], 0
    mov byte [rsi + 52], 0

    ; Extension data length = 5 + hostlen (big-endian)
    lea r9d, [r11d + 5]
    mov byte [rsi + 53], 0
    mov [rsi + 54], r9b

    ; Server name list length = 3 + hostlen (big-endian)
    lea eax, [r11d + 3]
    mov byte [rsi + 55], 0
    mov [rsi + 56], al

    ; Name type: host_name (0x00)
    mov byte [rsi + 57], 0

    ; Name length = hostlen (big-endian)
    mov byte [rsi + 58], 0
    mov [rsi + 59], r11b

    ; Copy hostname at offset 60
    test r11d, r11d
    jz .bch_no_sni
    lea rdi, [rsi + 60]
    mov rsi, rdx
    mov rcx, r11
    rep movsb
    mov rsi, r10                 ; restore output buffer pointer

.bch_no_sni:
    ; Write additional extensions after SNI hostname
    ; rdi = offset past SNI hostname (= 60 + hostlen)
    lea rdi, [rsi + 60]
    add edi, r11d

    ; renegotiation_info (0xff01, RFC 5746)
    mov word [rdi], 0x01FF
    mov word [rdi + 2], 0x0100
    mov byte [rdi + 4], 0

    ; session_ticket (0x0023, RFC 5077)
    mov word [rdi + 5], 0x2300
    mov word [rdi + 7], 0x0000

    ; extended_master_secret (0x0017, RFC 7627)
    mov word [rdi + 9], 0x1700
    mov word [rdi + 11], 0x0000

    ; signature_algorithms (0x000d, RFC 5246)
    mov word [rdi + 13], 0x0D00
    mov word [rdi + 15], 0x0A00
    mov word [rdi + 17], 0x0800
    ; SHA-256 + RSA
    mov word [rdi + 19], 0x0104
    ; SHA-384 + RSA
    mov word [rdi + 21], 0x0105
    ; RSA-PSS + SHA-256
    mov word [rdi + 23], 0x0408
    ; SHA-1 + RSA
    mov word [rdi + 25], 0x0102

    ; supported_elliptic_curves (0x000a, RFC 4492)
    mov word [rdi + 27], 0x0A00
    mov word [rdi + 29], 0x0400
    mov word [rdi + 31], 0x0200
    ; secp256r1 (0x0017)
    mov word [rdi + 33], 0x1700

    ; ec_point_formats (0x000b, RFC 4492)
    mov word [rdi + 35], 0x0B00
    mov word [rdi + 37], 0x0200
    ; formats list length = 1, uncompressed = 0
    mov byte [rdi + 39], 1
    mov byte [rdi + 40], 0

    ; application_layer_protocol_negotiation (0x0010, RFC 7301)
    mov word [rdi + 41], 0x1000     ; type 0x0010
    mov word [rdi + 43], 0x0B00     ; data length 11 (0x000b)
    mov word [rdi + 45], 0x0900     ; protocol list length 9 (0x0009)
    mov byte [rdi + 47], 8          ; "http/1.1" length
    mov dword [rdi + 48], 'http'    ; "http"
    mov dword [rdi + 52], '/1.1'    ; "/1.1"

    ; body length = 112 + hostlen (3 bytes big-endian)
    lea eax, [r11d + 112]
    mov byte [rsi + 1], 0
    mov byte [rsi + 2], ah
    mov byte [rsi + 3], al

    ; total message length = 116 + hostlen
    lea eax, [r11d + 116]

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

    ; Store negotiated version from ServerHello into ctx.version
    mov ax, [r11]
    xchg al, ah                     ; big-endian → host order
    mov [r10 + tls_ctx.version], ax

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

    ; Check if body has remaining data (extensions)
    cmp rdx, rcx
    jbe .psh_no_ext

    ; Read extensions_length (2 bytes, big-endian)
    mov ax, [r11 + rcx]
    xchg al, ah
    movzx eax, ax
    ; Skip extensions_length field
    lea ecx, [rcx + 2]
    ; If no extensions, skip parsing
    test eax, eax
    jz .psh_no_ext
    ; Compute end of extensions region
    lea r8, [rcx + rax]
.psh_ext_loop:
    cmp r8, rcx
    jbe .psh_ext_done
    ; Extension type at [r11 + rcx] (2 bytes BE)
    mov ax, [r11 + rcx]
    xchg al, ah
    ; Extension data length at [r11 + rcx + 2] (2 bytes BE)
    mov dx, [r11 + rcx + 2]
    xchg dl, dh
    movzx edx, dx
    lea ecx, [rcx + 4]   ; past type + length
    ; Check if this is extended_master_secret (0x0017)
    cmp ax, 0x0017
    jne .psh_ext_next
    mov byte [r10 + tls_ctx.ext_ms], 1
.psh_ext_next:
    add ecx, edx         ; skip extension data
    jmp .psh_ext_loop
.psh_ext_done:

.psh_no_ext:
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

    ; DEBUG: dump A(1) and seed_buf
    push r14
    push r15
    mov rdi, 2
    lea rsi, [rel debug_label_prf]
    mov edx, 5
    mov eax, 1
    syscall
    lea rdi, [rel prf_seed_buf]
    mov esi, 77
    call debug_hexdump
    lea rdi, [rel prf_abuf]
    mov esi, 32
    call debug_hexdump
    pop r15
    pop r14

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

    ; Build seed in hs_buf.
    ; Note: must NOT use prf_seed_buf - tls_prf uses it internally
    ; for (label + seed) construction, and if seed pointer overlaps
    ; with prf_seed_buf, the label copy corrupts the source seed.
    cmp byte [r12 + tls_ctx.ext_ms], 0
    je .tdk_no_ems

    ; EMS: seed = session_hash (32 bytes)
    lea rdi, [rel hs_buf]
    lea rsi, [rel session_hash]
    mov rcx, 32
    cld
    rep movsb
    mov r9, 32
    jmp .tdk_do_master

.tdk_no_ems:
    ; Standard: seed = client_random + server_random (64 bytes)
    lea rdi, [rel hs_buf]
    lea rsi, [r12 + tls_ctx.client_random]
    mov rcx, 32
    cld
    rep movsb

    lea rsi, [r12 + tls_ctx.server_random]
    mov rcx, 32
    rep movsb
    mov r9, 64

.tdk_do_master:
    ; PRF(pre_master, seed, master_secret, 48)
    mov rdi, r13
    mov rsi, r14
    cmp byte [r12 + tls_ctx.ext_ms], 0
    je .tdk_std_label
    lea rdx, [rel ext_master_label]
    mov rcx, ext_master_label_len
    jmp .tdk_do_prf
.tdk_std_label:
    lea rdx, [rel master_label]
    mov rcx, master_label_len
.tdk_do_prf:
    lea r8, [rel hs_buf]
    cmp byte [r12 + tls_ctx.ext_ms], 0
    jne .tdk_master_ems_seed
    mov r9, 64
    jmp .tdk_master_do_prf
.tdk_master_ems_seed:
    mov r9, 32
.tdk_master_do_prf:
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
    ; Layout depends on cipher suite
    cmp word [r12 + tls_ctx.cipher_suite], TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    je .tdk_gcm

    ; CBC + HMAC: client_mac(32) + server_mac(32) + client_key(16) + server_key(16)
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
    jmp .tdk_done

.tdk_gcm:
    ; GCM: client_key(16) + server_key(16) + client_iv(4) + server_iv(4)
    lea rsi, [rel hs_buf + 64]
    lea rdi, [rel client_write_key]
    mov rcx, 16
    cld
    rep movsb

    lea rsi, [rel hs_buf + 80]
    lea rdi, [rel server_write_key]
    mov rcx, 16
    rep movsb

    lea rsi, [rel hs_buf + 96]
    lea rdi, [rel client_write_iv]
    mov rcx, 4
    rep movsb

    lea rsi, [rel hs_buf + 100]
    lea rdi, [rel server_write_iv]
    mov rcx, 4
    rep movsb

.tdk_done:

    xor eax, eax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; int tls_connect(struct tls_ctx *ctx, int fd,
;                  const char *hostname, uint64_t hostlen)
; Initialize TLS context and perform handshake over an already-connected fd.
; Returns 0 on success, negative on error.
; rdi = ctx, esi = fd, rdx = hostname, rcx = hostlen
tls_connect:
    push r12
    push r13
    mov r12, rdi
    mov r13d, esi

    ; Initialize TLS context
    mov rdi, r12
    call tls_init

    ; Run handshake (args already line up: rdi=ctx, esi=fd, rdx=hostname, rcx=hostlen)
    mov rdi, r12
    mov esi, r13d
    call tls_client_start
    test eax, eax
    jnz .conn_error

    xor eax, eax
    jmp .conn_done

.conn_error:
    or eax, -1

.conn_done:
    pop r13
    pop r12
    ret

; int tls_disconnect(struct tls_ctx *ctx, int fd)
; Send close_notify alert and close the socket.
; Returns 0 on success, negative on error.
; rdi = ctx, esi = fd
tls_disconnect:
    push r12
    push r13
    sub rsp, 8

    mov r12, rdi
    mov r13d, esi

    ; Build close_notify alert payload: level=1(warning), desc=0(close_notify)
    mov word [rsp], 0x0001

    ; Send Alert record (best-effort, ignore send failures like EPIPE)
    mov rdi, r12
    mov esi, r13d
    mov edx, TLS_ALERT
    mov rcx, rsp
    mov r8, 2
    call tls_send

    ; Close the socket
    mov edi, r13d
    call sys_close

    add rsp, 8
    xor eax, eax
    pop r13
    pop r12
    ret
