; The main entry point for slack-asm
BITS 64

default rel

%define SYS_write  1
%define SYS_exit   60

%define STDOUT     1
%define AF_INET    2
%define SOCK_STREAM 1
%define TLS_APPLICATION_DATA 23

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
extern http_start_request
extern http_add_header
extern http_finish_headers
extern http_add_body
extern http_parse_response
extern http_body_ptr
extern http_body_len
extern http_status

section .rodata
banner:          db "slack-asm starting...", 10
banner_len:      equ $ - banner
https_ok_msg:    db "HTTPS request OK, status: ", 0
https_ok_msg_len: equ $ - https_ok_msg
https_fail_msg:  db "HTTPS request failed", 10
https_fail_msg_len: equ $ - https_fail_msg
dns_fail_msg:    db "DNS resolution failed", 10
dns_fail_msg_len: equ $ - dns_fail_msg
tls_fail_msg:    db "TLS fail: ", 0
tls_fail_msg_len: equ $ - tls_fail_msg
connect_fail_msg: db "Connection failed", 10
connect_fail_msg_len: equ $ - connect_fail_msg
body_msg:        db "Body: ", 0
body_msg_len:    equ $ - body_msg
newline:         db 10

http_host_name:  db "Host"
http_host_name_len: equ $ - http_host_name
http_host_val:   db "localhost"
http_host_val_len: equ $ - http_host_val
http_get_path:   db "/"
http_get_path_len: equ $ - http_get_path
http_get_method: db "GET"
http_get_method_len: equ $ - http_get_method

section .bss
read_buf:        resb 4096
tls_ctx_buf:     resb 118
recv_buf:        resb 4096
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
    call test_harness
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

; Demo an HTTPS GET request to www.example.com:443
https_demo:
    push rbx
    push r12

    ; Skip DNS, use hardcoded localhost 127.0.0.1:4443
    mov r12d, 0x7f000001          ; 127.0.0.1 in host byte order

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
    mov esi, 4443                 ; port
    mov edx, r12d                 ; IP
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

    ; Receive response
    lea rdi, [tls_ctx_buf]
    mov esi, ebx
    lea rdx, [recv_type]
    lea rcx, [recv_buf]
    lea r8, [recv_len]
    call tls_recv
    test eax, eax
    jnz .disconnect

    ; Parse HTTP response
    lea rdi, [recv_buf]
    mov rsi, [recv_len]
    call http_parse_response
    test eax, eax
    js .disconnect

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
    pop r12
    pop rbx
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
