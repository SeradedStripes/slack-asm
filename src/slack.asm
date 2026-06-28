; The main entry point for slack-asm
BITS 64

default rel

%define SYS_write  1
%define SYS_exit   60
%define STDERR     2
%define STDOUT     1
%define AF_INET    2
%define SOCK_STREAM 1
%define TLS_APPLICATION_DATA 23
%define RECV_BUF_SIZE  65536

; Target server configuration
%define HTTPS_HOST     "example.com"
%define HTTPS_HOST_LEN 11
%define HTTPS_PORT     443
; For local test server (openssl s_server), use:
;   %define HTTPS_HOST     "localhost"
;   %define HTTPS_HOST_LEN 9
;   %define HTTPS_PORT     4443

extern test_harness
extern tls_connect
extern tls_disconnect
extern tls_send
extern tls_recv
extern sys_socket
extern sys_connect
extern sys_close
extern make_sockaddr_in
extern dns_resolve
extern master_secret
extern client_write_mac_key
extern server_write_mac_key
extern client_write_key
extern server_write_key
extern http_start_request
extern http_add_header
extern http_finish_headers
extern http_add_body
extern http_parse_response
extern http_body_ptr
extern http_body_len
extern http_status
extern http_chunked
extern http_decode_chunked

section .rodata
banner:          db "slack-asm starting...", 10
banner_len:      equ $ - banner
https_ok_msg:    db "HTTPS request OK, status: "
https_ok_msg_len: equ $ - https_ok_msg
https_fail_msg:  db "HTTPS request failed", 10
https_fail_msg_len: equ $ - https_fail_msg
dns_fail_msg:    db "DNS resolution failed", 10
dns_fail_msg_len: equ $ - dns_fail_msg
tls_fail_msg:    db "TLS fail: "
tls_fail_msg_len: equ $ - tls_fail_msg
connect_fail_msg: db "Connection failed", 10
connect_fail_msg_len: equ $ - connect_fail_msg
body_msg:        db "Body: "
body_msg_len:    equ $ - body_msg
newline:         db 10

http_host_name:  db "Host"
http_host_name_len: equ $ - http_host_name
http_host_val:   db HTTPS_HOST
http_host_val_len: equ HTTPS_HOST_LEN
http_ua_name:    db "User-Agent"
http_ua_name_len: equ $ - http_ua_name
http_ua_val:     db "slack-asm/0.1"
http_ua_val_len: equ $ - http_ua_val
http_conn_name:  db "Connection"
http_conn_name_len: equ $ - http_conn_name
http_conn_val:   db "close"
http_conn_val_len: equ $ - http_conn_val
http_get_path:   db "/"
http_get_path_len: equ $ - http_get_path
http_get_method: db "GET"
http_get_method_len: equ $ - http_get_method

section .bss
read_buf:        resb 4096
tls_ctx_buf:     resb 119
recv_buf:        resb RECV_BUF_SIZE
recv_type:       resb 1
recv_len:        resq 1
sockaddr:        resb 16

section .text
global _start

_start:
    xor ebp, ebp
    call main
    mov edi, eax
    mov eax, SYS_exit
    syscall

main:
    call print_banner
    ; call test_harness  ; SKIP for debugging
    call https_demo
    xor eax, eax
    ret

print_banner:
    mov eax, SYS_write
    mov edi, STDOUT
    lea rsi, [banner]
    mov edx, banner_len
    syscall
    ret

; Demo an HTTPS GET request
https_demo:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; Resolve hostname to IP via DNS (or use fallback)
    lea rdi, [http_host_val]
    mov esi, http_host_val_len
    call dns_resolve
    mov r15d, eax
    test r15d, r15d
    jnz .have_ip
    ; DNS failed — try localhost 127.0.0.1 as fallback
    mov r15d, 0x7f000001
.have_ip:

    ; Create TCP socket
    mov edi, AF_INET
    mov esi, SOCK_STREAM
    xor edx, edx
    call sys_socket
    test eax, eax
    js .demo_done
    mov ebx, eax                  ; fd

    ; Connect to target
    lea rdi, [sockaddr]
    mov esi, HTTPS_PORT
    mov edx, r15d                 ; IP
    call make_sockaddr_in

    mov edi, ebx
    lea rsi, [sockaddr]
    mov edx, 16
    call sys_connect
    test eax, eax
    jnz .close_sock

    ; TLS handshake
    lea rdi, [tls_ctx_buf]
    mov esi, ebx
    lea rdx, [http_host_val]
    mov ecx, http_host_val_len
    call tls_connect
    test eax, eax
    jz .tls_ok
    push rax
    lea rsi, [tls_fail_msg]
    mov edx, tls_fail_msg_len
    call print_str
    pop rax
    call print_uint64
    mov rsi, newline
    mov edx, 1
    call print_str
    call dump_keys
    jmp .disconnect
.tls_ok:

    ; Build HTTP request in read_buf
    lea rdi, [read_buf]
    lea rsi, [http_get_method]
    mov edx, http_get_method_len
    lea rcx, [http_get_path]
    mov r8d, http_get_path_len
    call http_start_request
    mov r12d, eax                 ; bytes written so far

    lea rdi, [read_buf + r12]
    lea rsi, [http_host_name]
    mov edx, http_host_name_len
    lea rcx, [http_host_val]
    mov r8d, http_host_val_len
    call http_add_header
    add r12d, eax

    lea rdi, [read_buf + r12]
    lea rsi, [http_conn_name]
    mov edx, http_conn_name_len
    lea rcx, [http_conn_val]
    mov r8d, http_conn_val_len
    call http_add_header
    add r12d, eax

    lea rdi, [read_buf + r12]
    lea rsi, [http_ua_name]
    mov edx, http_ua_name_len
    lea rcx, [http_ua_val]
    mov r8d, http_ua_val_len
    call http_add_header
    add r12d, eax

    lea rdi, [read_buf + r12]
    call http_finish_headers
    add r12d, eax

    ; Send HTTP request via TLS
    lea rdi, [tls_ctx_buf]
    mov esi, ebx
    mov edx, TLS_APPLICATION_DATA
    lea rcx, [read_buf]
    mov r8d, r12d
    call tls_send
    test rax, rax
    js .disconnect

    ; Receive full HTTP response across multiple TLS records
    xor r14d, r14d                ; total bytes accumulated
.recv_loop:
    lea rdi, [tls_ctx_buf]
    mov esi, ebx
    lea rdx, [recv_type]
    lea rcx, [recv_buf + r14]
    lea r8, [recv_len]
    call tls_recv
    test eax, eax
    jnz .disconnect
    cmp byte [recv_type], TLS_APPLICATION_DATA
    jne .recv_done
    mov eax, [recv_len]
    test eax, eax
    jz .recv_done
    add r14d, eax
    ; Check remaining buffer space (need room for at least one more record)
    cmp r14d, RECV_BUF_SIZE - 16384
    jb .recv_loop
.recv_done:

    ; Check we received something
    test r14d, r14d
    jz .disconnect

    ; Parse HTTP response from accumulated buffer
    lea rdi, [recv_buf]
    mov rsi, r14
    call http_parse_response
    test eax, eax
    js .disconnect

    ; If chunked transfer encoding, decode body in-place
    cmp byte [rel http_chunked], 0
    je .no_decode
    mov rdi, [rel http_body_ptr]
    mov rsi, [rel http_body_len]
    call http_decode_chunked
    test eax, eax
    js .disconnect
    mov [rel http_body_len], rax
.no_decode:

    ; Print status code
    lea rsi, [https_ok_msg]
    mov edx, https_ok_msg_len
    call print_str

    mov eax, [rel http_status]
    call print_uint64

    mov rsi, newline
    mov edx, 1
    call print_str

    ; Print body
    mov rax, [rel http_body_len]
    test rax, rax
    jz .disconnect

    lea rsi, [body_msg]
    mov edx, body_msg_len
    call print_str

    mov rsi, [rel http_body_ptr]
    mov edx, [rel http_body_len]
    call print_str

    mov rsi, newline
    mov edx, 1
    call print_str

.disconnect:
    lea rdi, [tls_ctx_buf]
    mov esi, ebx
    call tls_disconnect
    jmp .demo_done

.close_sock:
    mov edi, ebx
    call sys_close

.demo_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Dump derived TLS keys for debugging (placeholder)
dump_keys:
    ret

; Print a string (rsi = ptr, edx = len)
print_str:
    mov eax, SYS_write
    mov edi, STDOUT
    syscall
    ret

; Print a uint64 in decimal (eax = value)
print_uint64:
    push rbx
    push r12
    sub rsp, 24

    mov r12d, eax
    lea rbx, [rsp + 20]
    mov byte [rbx], 0
    dec rbx
    mov byte [rbx], 10

    mov eax, r12d
    mov r12d, 10

.pu_loop:
    dec rbx
    xor edx, edx
    div r12d
    add dl, '0'
    mov [rbx], dl
    test eax, eax
    jnz .pu_loop

    mov rsi, rbx
    lea rax, [rsp + 21]
    sub rax, rbx
    mov edx, eax
    call print_str

    add rsp, 24
    pop r12
    pop rbx
    ret
