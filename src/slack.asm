; slack-asm: Slack client in x86-64 assembly
BITS 64
default rel

%define SYS_read   0
%define SYS_write  1
%define SYS_open   2
%define SYS_close  3
%define SYS_exit   60
%define STDOUT     1
%define O_RDONLY   0
%define AF_INET    2
%define SOCK_STREAM 1
%define TLS_APPLICATION_DATA 23
%define RECV_BUF_SIZE  65536

%define SLACK_API_HOST "slack.com"
%define SLACK_API_HOST_LEN 9
%define SLACK_API_PORT 443
%define SLACK_API_PATH "/api/apps.connections.open"

extern tls_connect, tls_disconnect, tls_send, tls_recv
extern sys_socket, sys_connect, sys_close
extern make_sockaddr_in, dns_resolve
extern http_start_request, http_add_header, http_finish_headers
extern http_parse_response, http_body_ptr, http_body_len, http_status, http_chunked
extern http_decode_chunked
extern ws_send_frame, ws_recv_frame
extern json_get_str, parse_wss_url
extern debug_putc
extern base64_encode

; WebSocket opcodes
%define WS_TEXT  0x1
%define WS_CLOSE 0x8
%define WS_PING  0x9
%define WS_PONG  0xA

section .rodata
banner:          db "slack-asm", 10
banner_len:      equ $ - banner
crlf:            db 10
tag_wsurl:       db "ws url: "
tag_wsurl_len:   equ $ - tag_wsurl
tag_ok:          db "OK", 10
tag_ok_len:      equ $ - tag_ok
tag_fail:        db "FAIL "
tag_fail_len:    equ $ - tag_fail
tag_rcvd:        db "RCVD: "
tag_rcvd_len:    equ $ - tag_rcvd
tag_connected:   db "WS connected", 10
tag_connected_len: equ $ - tag_connected

; Target strings (must be labels, not just defines)
api_host:        db SLACK_API_HOST
api_host_len:    equ $ - api_host
api_path:        db SLACK_API_PATH
api_path_len:    equ $ - api_path

; HTTP header data
m_post:          db "POST"
m_post_len:      equ $ - m_post
h_host:          db "Host"
h_host_len:      equ $ - h_host
h_ct:            db "Content-Type"
h_ct_len:        equ $ - h_ct
ct_json:         db "application/json"
ct_json_len:     equ $ - ct_json
h_auth:          db "Authorization"
h_auth_len:      equ $ - h_auth
h_close:         db "Connection"
h_close_len:     equ $ - h_close
v_close:         db "close"
v_close_len:     equ $ - v_close
h_accept:        db "Accept"
h_accept_len:    equ $ - h_accept
v_accept:        db "*/*"
v_accept_len:    equ $ - v_accept
h_clen:          db "Content-Length"
h_clen_len:      equ $ - h_clen
v_clen:          db "2"
v_clen_len:      equ $ - v_clen

; WebSocket upgrade headers
h_upgrade:       db "Upgrade"
h_upgrade_len:   equ $ - h_upgrade
v_upgrade:       db "websocket"
v_upgrade_len:   equ $ - v_upgrade
h_wsconn:        db "Connection"
h_wsconn_len:    equ $ - h_wsconn
v_wsconn:        db "Upgrade"
v_wsconn_len:    equ $ - v_wsconn
h_wskey:         db "Sec-WebSocket-Key"
h_wskey_len:     equ $ - h_wskey
h_wsver:         db "Sec-WebSocket-Version"
h_wsver_len:     equ $ - h_wsver
v_wsver:         db "13"
v_wsver_len:     equ $ - v_wsver

key_json:        db '"url"'
key_json_len:    equ 5
dotenv:          db ".env", 0
slack_token_key: db "SLACK_TOKEN="

section .bss
api_tls:    resb 120
ws_tls:     resb 120
reqbuf:     resb 4096
recvbuf:    resb RECV_BUF_SIZE
ws_url:     resb 512        ; WebSocket URL string
ws_host:    resb 128        ; WebSocket hostname
ws_path:    resb 256        ; WebSocket path
ws_key:     resb 64         ; random bytes + base64 WebSocket key
sockaddr:   resb 16
rtype:      resb 1
rlen:       resq 1
wstype:     resb 1
wslen:      resq 1
ws_host_len: resq 1
ws_path_len: resq 1
envbuf:     resb 4096           ; .env file read buffer
envtoken:   resb 256            ; extracted token from .env

section .text
global _start

_start:
    pop rcx                     ; argc
    cmp ecx, 2
    jge .from_argv

    ; Try reading token from .env
    call load_env_token
    test eax, eax
    jnz .go_env

.usage:
    lea rsi, [tag_fail]
    mov edx, tag_fail_len
    call pstr
    mov edi, 1
    mov eax, SYS_exit
    syscall

.from_argv:
    pop rax                     ; argv[0]
    pop r12                     ; argv[1] = bot token
    ; strlen
    mov r13, r12
    xor eax, eax
.len:
    cmp byte [r13 + rax], 0
    je .go
    inc rax
    jmp .len
.go:
    mov r13, rax                ; token length
    xor ebp, ebp
    call main
    mov edi, eax
    mov eax, SYS_exit
    syscall

.go_env:
    mov r12, rdi                ; token ptr from load_env_token
    mov r13, rsi                ; token len
    xor ebp, ebp
    call main
    mov edi, eax
    mov eax, SYS_exit
    syscall

main:
    push r12
    push r13
    push r14
    push r15
    push rbx

    call print_banner

    ; Step 1: Call Slack API -> get WebSocket URL
    mov rdi, r12                ; token
    mov rsi, r13                ; token len
    call slack_api
    mov r14d, eax               ; r14d = URL length
    test r14d, r14d
    jz .fail

    ; Print URL
    lea rsi, [tag_wsurl]
    mov edx, tag_wsurl_len
    call pstr
    lea rsi, [ws_url]
    mov edx, r14d
    call pstr
    call pnl

    ; Step 2: Parse "wss://host:port/path" inline
    lea r12, [ws_url]
    mov r13, r14

    cmp r13, 6
    jb .fail
    cmp dword [r12], 'wss:'
    jne .fail
    cmp word [r12 + 4], '//'
    jne .fail
    add r12, 6
    sub r13, 6

    xor ecx, ecx
.scan_host:
    cmp rcx, r13
    jae .got_host
    cmp byte [r12 + rcx], '/'
    je .got_host
    cmp byte [r12 + rcx], ':'
    je .got_host_port
    inc rcx
    jmp .scan_host
.got_host_port:
    inc rcx
.scan_port:
    cmp rcx, r13
    jae .got_host
    cmp byte [r12 + rcx], '/'
    je .got_host
    inc rcx
    jmp .scan_port
.got_host:
    mov r15d, ecx
    mov [rel ws_host_len], rcx
    lea rdi, [ws_host]
    mov rsi, r12
    rep movsb
    mov byte [ws_host + r15], 0

    lea r9, [r12 + r15]
    lea r8, [r12 + r13]
    cmp r9, r8
    jae .no_path
    cmp byte [r9], '/'
    jne .no_path
    mov rsi, r9
    mov rax, r8
    sub rax, r9
    mov rcx, rax
    cmp rcx, 255
    jbe .copy_path
    mov ecx, 255
.copy_path:
    mov [rel ws_path_len], rcx
    lea rdi, [ws_path]
    push rcx
    rep movsb
    pop rcx
    mov byte [ws_path + rcx], 0
    jmp .connect_ws
.no_path:
    mov qword [rel ws_path_len], 1
    mov byte [ws_path], '/'
    mov byte [ws_path + 1], 0

.connect_ws:
    ; Step 3: DNS resolve WS host
    lea rdi, [ws_host]
    mov esi, r15d
    call dns_resolve
    test eax, eax
    jz .fail
    mov ebx, eax

    ; Step 4: TCP connect :443
    mov edi, AF_INET
    mov esi, SOCK_STREAM
    xor edx, edx
    call sys_socket
    test eax, eax
    js .fail
    mov r14d, eax
    lea rdi, [sockaddr]
    mov esi, 443
    mov edx, ebx
    call make_sockaddr_in
    mov edi, r14d
    lea rsi, [sockaddr]
    mov edx, 16
    call sys_connect
    test eax, eax
    jnz .close_sock

    ; Step 5: TLS connect
    lea rdi, [ws_tls]
    mov esi, r14d
    lea rdx, [ws_host]
    mov ecx, [rel ws_host_len]
    call tls_connect
    test eax, eax
    jnz .close_sock

    ; Step 6: WS key (16 random bytes -> base64)
    lea rdi, [ws_key]
    mov esi, 16
    xor edx, edx
    mov eax, 318
    syscall
    lea rdi, [ws_key]
    mov esi, 16
    lea rdx, [ws_key + 16]
    call base64_encode
    mov ebp, eax

    ; Step 7: Build WS upgrade request in reqbuf
    xor r15d, r15d

    ; "GET /path HTTP/1.1" CRLF
    mov dword [reqbuf + r15], 'GET '
    add r15d, 4
    lea rdi, [reqbuf + r15]
    lea rsi, [ws_path]
    mov rcx, [rel ws_path_len]
    cld
    rep movsb
    add r15d, [rel ws_path_len]
    mov byte [reqbuf + r15 + 0], ' '
    mov byte [reqbuf + r15 + 1], 'H'
    mov byte [reqbuf + r15 + 2], 'T'
    mov byte [reqbuf + r15 + 3], 'T'
    mov byte [reqbuf + r15 + 4], 'P'
    mov byte [reqbuf + r15 + 5], '/'
    mov byte [reqbuf + r15 + 6], '1'
    mov byte [reqbuf + r15 + 7], '.'
    mov byte [reqbuf + r15 + 8], '1'
    mov byte [reqbuf + r15 + 9], 0x0D
    mov byte [reqbuf + r15 + 10], 0x0A
    add r15d, 11

    ; "Host: host" CRLF
    mov byte [reqbuf + r15 + 0], 'H'
    mov byte [reqbuf + r15 + 1], 'o'
    mov byte [reqbuf + r15 + 2], 's'
    mov byte [reqbuf + r15 + 3], 't'
    mov byte [reqbuf + r15 + 4], ':'
    mov byte [reqbuf + r15 + 5], ' '
    add r15d, 6
    lea rdi, [reqbuf + r15]
    lea rsi, [ws_host]
    mov rcx, [rel ws_host_len]
    rep movsb
    add r15d, [rel ws_host_len]
    mov byte [reqbuf + r15 + 0], 0x0D
    mov byte [reqbuf + r15 + 1], 0x0A
    add r15d, 2

    ; "Upgrade: websocket" CRLF
    mov byte [reqbuf + r15 + 0], 'U'
    mov byte [reqbuf + r15 + 1], 'p'
    mov byte [reqbuf + r15 + 2], 'g'
    mov byte [reqbuf + r15 + 3], 'r'
    mov byte [reqbuf + r15 + 4], 'a'
    mov byte [reqbuf + r15 + 5], 'd'
    mov byte [reqbuf + r15 + 6], 'e'
    mov byte [reqbuf + r15 + 7], ':'
    mov byte [reqbuf + r15 + 8], ' '
    add r15d, 9
    mov byte [reqbuf + r15 + 0], 'w'
    mov byte [reqbuf + r15 + 1], 'e'
    mov byte [reqbuf + r15 + 2], 'b'
    mov byte [reqbuf + r15 + 3], 's'
    mov byte [reqbuf + r15 + 4], 'o'
    mov byte [reqbuf + r15 + 5], 'c'
    mov byte [reqbuf + r15 + 6], 'k'
    mov byte [reqbuf + r15 + 7], 'e'
    mov byte [reqbuf + r15 + 8], 't'
    add r15d, 9
    mov byte [reqbuf + r15 + 0], 0x0D
    mov byte [reqbuf + r15 + 1], 0x0A
    add r15d, 2

    ; "Connection: Upgrade" CRLF
    mov byte [reqbuf + r15 + 0], 'C'
    mov byte [reqbuf + r15 + 1], 'o'
    mov byte [reqbuf + r15 + 2], 'n'
    mov byte [reqbuf + r15 + 3], 'n'
    mov byte [reqbuf + r15 + 4], 'e'
    mov byte [reqbuf + r15 + 5], 'c'
    mov byte [reqbuf + r15 + 6], 't'
    mov byte [reqbuf + r15 + 7], 'i'
    mov byte [reqbuf + r15 + 8], 'o'
    mov byte [reqbuf + r15 + 9], 'n'
    mov byte [reqbuf + r15 + 10], ':'
    mov byte [reqbuf + r15 + 11], ' '
    add r15d, 12
    mov byte [reqbuf + r15 + 0], 'U'
    mov byte [reqbuf + r15 + 1], 'p'
    mov byte [reqbuf + r15 + 2], 'g'
    mov byte [reqbuf + r15 + 3], 'r'
    mov byte [reqbuf + r15 + 4], 'a'
    mov byte [reqbuf + r15 + 5], 'd'
    mov byte [reqbuf + r15 + 6], 'e'
    add r15d, 7
    mov byte [reqbuf + r15 + 0], 0x0D
    mov byte [reqbuf + r15 + 1], 0x0A
    add r15d, 2

    ; "Sec-WebSocket-Key: <b64>" CRLF
    mov byte [reqbuf + r15 + 0], 'S'
    mov byte [reqbuf + r15 + 1], 'e'
    mov byte [reqbuf + r15 + 2], 'c'
    mov byte [reqbuf + r15 + 3], '-'
    mov byte [reqbuf + r15 + 4], 'W'
    mov byte [reqbuf + r15 + 5], 'e'
    mov byte [reqbuf + r15 + 6], 'b'
    mov byte [reqbuf + r15 + 7], 'S'
    mov byte [reqbuf + r15 + 8], 'o'
    mov byte [reqbuf + r15 + 9], 'c'
    mov byte [reqbuf + r15 + 10], 'k'
    mov byte [reqbuf + r15 + 11], 'e'
    mov byte [reqbuf + r15 + 12], 't'
    mov byte [reqbuf + r15 + 13], '-'
    mov byte [reqbuf + r15 + 14], 'K'
    mov byte [reqbuf + r15 + 15], 'e'
    mov byte [reqbuf + r15 + 16], 'y'
    mov byte [reqbuf + r15 + 17], ':'
    mov byte [reqbuf + r15 + 18], ' '
    add r15d, 19
    lea rdi, [reqbuf + r15]
    lea rsi, [ws_key + 16]
    mov ecx, ebp
    rep movsb
    add r15d, ebp
    mov byte [reqbuf + r15 + 0], 0x0D
    mov byte [reqbuf + r15 + 1], 0x0A
    add r15d, 2

    ; "Sec-WebSocket-Version: 13" CRLF
    mov byte [reqbuf + r15 + 0], 'S'
    mov byte [reqbuf + r15 + 1], 'e'
    mov byte [reqbuf + r15 + 2], 'c'
    mov byte [reqbuf + r15 + 3], '-'
    mov byte [reqbuf + r15 + 4], 'W'
    mov byte [reqbuf + r15 + 5], 'e'
    mov byte [reqbuf + r15 + 6], 'b'
    mov byte [reqbuf + r15 + 7], 'S'
    mov byte [reqbuf + r15 + 8], 'o'
    mov byte [reqbuf + r15 + 9], 'c'
    mov byte [reqbuf + r15 + 10], 'k'
    mov byte [reqbuf + r15 + 11], 'e'
    mov byte [reqbuf + r15 + 12], 't'
    mov byte [reqbuf + r15 + 13], '-'
    mov byte [reqbuf + r15 + 14], 'V'
    mov byte [reqbuf + r15 + 15], 'e'
    mov byte [reqbuf + r15 + 16], 'r'
    mov byte [reqbuf + r15 + 17], 's'
    mov byte [reqbuf + r15 + 18], 'i'
    mov byte [reqbuf + r15 + 19], 'o'
    mov byte [reqbuf + r15 + 20], 'n'
    mov byte [reqbuf + r15 + 21], ':'
    mov byte [reqbuf + r15 + 22], ' '
    add r15d, 23
    mov byte [reqbuf + r15 + 0], '1'
    mov byte [reqbuf + r15 + 1], '3'
    mov byte [reqbuf + r15 + 2], 0x0D
    mov byte [reqbuf + r15 + 3], 0x0A
    add r15d, 4

    ; final CRLF
    mov byte [reqbuf + r15 + 0], 0x0D
    mov byte [reqbuf + r15 + 1], 0x0A
    add r15d, 2

    ; Send upgrade request
    lea rdi, [ws_tls]
    mov esi, r14d
    mov edx, TLS_APPLICATION_DATA
    lea rcx, [reqbuf]
    mov r8d, r15d
    call tls_send
    test rax, rax
    js .close_ws

    ; Step 8: Receive upgrade response
    xor ebp, ebp
.ws_recv:
    lea rdi, [ws_tls]
    mov esi, r14d
    lea rdx, [rtype]
    lea rcx, [recvbuf + rbp]
    lea r8, [rlen]
    call tls_recv
    test eax, eax
    jnz .ws_recv_done
    cmp byte [rtype], TLS_APPLICATION_DATA
    jne .ws_recv_done
    mov eax, [rlen]
    test eax, eax
    jz .ws_recv_done
    add ebp, eax
    cmp ebp, RECV_BUF_SIZE - 16384
    jb .ws_recv
.ws_recv_done:
    test ebp, ebp
    jz .close_ws

    ; Check status 101
    lea rdi, [recvbuf]
    mov esi, ebp
    call http_parse_response
    test eax, eax
    js .close_ws
    cmp dword [rel http_status], 101
    jne .bad_ws

    ; Connected, Print status
    lea rsi, [tag_connected]
    mov edx, tag_connected_len
    call pstr
    jmp .frame_loop

.bad_ws:
    lea rsi, [tag_fail]
    mov edx, tag_fail_len
    call pstr
    mov eax, [rel http_status]
    call pnum
    call pnl
    jmp .close_ws

    ; Step 9: Frame event loop
.frame_loop:
    lea rdi, [ws_tls]
    mov esi, r14d
    lea rdx, [wstype]
    lea rcx, [recvbuf]
    lea r8, [wslen]
    call ws_recv_frame
    test eax, eax
    js .close_ws

    movzx eax, byte [rel wstype]
    cmp al, WS_TEXT
    je .got_text
    cmp al, WS_PING
    je .got_ping
    cmp al, WS_CLOSE
    je .close_ws
    jmp .frame_loop

.got_text:
    lea rsi, [tag_rcvd]
    mov edx, tag_rcvd_len
    call pstr
    lea rsi, [recvbuf]
    mov edx, [rel wslen]
    call pstr
    call pnl
    jmp .frame_loop

.got_ping:
    ; Echo pong
    lea rdi, [ws_tls]
    mov esi, r14d
    mov edx, WS_PONG
    xor ecx, ecx
    xor r8d, r8d
    call ws_send_frame
    jmp .frame_loop

.close_ws:
    lea rdi, [ws_tls]
    mov esi, r14d
    call tls_disconnect
    jmp .fail
.close_sock:
    mov edi, r14d
    call sys_close
.fail:
    mov eax, 1
.done:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; Do slack API call: POST to apps.connections.open
; rdi = token ptr, rsi = token len
; Returns eax = URL length (0 if error)
; WebSocket URL stored in ws_url buffer
slack_api:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                ; token ptr
    mov r13, rsi                ; token len

    ; DNS resolve slack.com
    lea rdi, [api_host]
    mov esi, api_host_len
    call dns_resolve
    test eax, eax
    jz .err_dns
    mov ebx, eax                ; IP

    ; Socket
    mov edi, AF_INET
    mov esi, SOCK_STREAM
    xor edx, edx
    call sys_socket
    test eax, eax
    js .err
    mov r14d, eax               ; fd

    ; Connect
    lea rdi, [sockaddr]
    mov esi, SLACK_API_PORT
    mov edx, ebx
    call make_sockaddr_in
    mov edi, r14d
    lea rsi, [sockaddr]
    mov edx, 16
    call sys_connect
    test eax, eax
    jnz .close

    ; TLS handshake
    lea rdi, [api_tls]
    mov esi, r14d
    lea rdx, [api_host]
    mov ecx, api_host_len
    call tls_connect
    test eax, eax
    jnz .close

    ; ---- Build POST request ----
    lea rdi, [reqbuf]
    lea rsi, [m_post]
    mov edx, m_post_len
    lea rcx, [api_path]
    mov r8d, api_path_len
    call http_start_request
    mov r15d, eax               ; bytes written

    ; Host header
    lea rdi, [reqbuf + r15]
    lea rsi, [h_host]
    mov edx, h_host_len
    lea rcx, [api_host]
    mov r8d, api_host_len
    call http_add_header
    add r15d, eax

    ; Content-Type: application/json
    lea rdi, [reqbuf + r15]
    lea rsi, [h_ct]
    mov edx, h_ct_len
    lea rcx, [ct_json]
    mov r8d, ct_json_len
    call http_add_header
    add r15d, eax

    ; Authorization: Bearer <token>
    ; Build value "Bearer xoxb-..." in ws_url buffer (safe to reuse since we don't need it yet)
    mov byte [ws_url], 'B'
    mov byte [ws_url + 1], 'e'
    mov byte [ws_url + 2], 'a'
    mov byte [ws_url + 3], 'r'
    mov byte [ws_url + 4], 'e'
    mov byte [ws_url + 5], 'r'
    mov byte [ws_url + 6], ' '
    lea rdi, [ws_url + 7]
    mov rsi, r12
    mov rcx, r13
    cld
    rep movsb
    lea ebp, [r13 + 7]          ; auth value length

    lea rdi, [reqbuf + r15]
    lea rsi, [h_auth]
    mov edx, h_auth_len
    lea rcx, [ws_url]
    mov r8d, ebp
    call http_add_header
    add r15d, eax

    ; Accept: */*
    lea rdi, [reqbuf + r15]
    lea rsi, [h_accept]
    mov edx, h_accept_len
    lea rcx, [v_accept]
    mov r8d, v_accept_len
    call http_add_header
    add r15d, eax

    ; Content-Length: 2
    lea rdi, [reqbuf + r15]
    lea rsi, [h_clen]
    mov edx, h_clen_len
    lea rcx, [v_clen]
    mov r8d, v_clen_len
    call http_add_header
    add r15d, eax

    ; Finish headers
    lea rdi, [reqbuf + r15]
    call http_finish_headers
    add r15d, eax

    ; Body: {}
    mov word [reqbuf + r15], '{}'
    add r15d, 2

    ; Debug: hex dump request
    lea rsi, [reqbuf]
    mov edx, r15d
    call hex_dump
    ; Send POST request via TLS
    lea rdi, [api_tls]
    mov esi, r14d
    mov edx, TLS_APPLICATION_DATA
    lea rcx, [reqbuf]
    mov r8d, r15d
    call tls_send
    test rax, rax
    js .disc

    ; ---- Receive response ----
    xor ebp, ebp                ; total bytes
.recv:
    lea rdi, [api_tls]
    mov esi, r14d
    lea rdx, [rtype]
    lea rcx, [recvbuf + rbp]
    lea r8, [rlen]
    call tls_recv
    test eax, eax
    jnz .disc
    cmp byte [rtype], TLS_APPLICATION_DATA
    jne .recv_done
    mov eax, [rlen]
    test eax, eax
    jz .recv_done
    add ebp, eax
    cmp ebp, RECV_BUF_SIZE - 16384
    jb .recv
.recv_done:
    test ebp, ebp
    jz .disc

    ; Debug: dump response
    lea rsi, [recvbuf]
    mov edx, ebp
    call hex_dump

    ; Parse HTTP
    lea rdi, [recvbuf]
    mov esi, ebp
    call http_parse_response
    test eax, eax
    js .disc

    ; Chunked decode if needed
    cmp byte [rel http_chunked], 0
    je .nochunk
    mov rdi, [rel http_body_ptr]
    mov rsi, [rel http_body_len]
    call http_decode_chunked
    test eax, eax
    js .disc
    mov [rel http_body_len], rax
.nochunk:

    ; Check status == 200
    cmp dword [rel http_status], 200
    jne .bad_status

    ; Find "url" in JSON body
    mov rdi, [rel http_body_ptr]
    mov rsi, [rel http_body_len]
    lea rdx, [key_json]
    mov rcx, key_json_len
    call json_get_str
    test rax, rax
    jz .bad_json

    ; Copy URL to ws_url buffer
    ; json_get_str returns: rax = ptr, edx = len
    mov r12, rax                ; src
    mov r13d, edx               ; len
    cmp r13d, 500               ; sanity
    ja .bad_json
    lea rdi, [ws_url]
    mov rsi, r12
    mov rcx, r13
    cld
    rep movsb
    mov byte [rdi], 0           ; null-terminate (optional)

    ; Disconnect
    lea rdi, [api_tls]
    mov esi, r14d
    call tls_disconnect

    mov eax, r13d               ; return URL length
    jmp .done

.bad_status:
    lea rsi, [tag_fail]
    mov edx, tag_fail_len
    call pstr
    mov eax, [rel http_status]
    call pnum
    call pnl
    jmp .disc

.bad_json:
    lea rsi, [tag_fail]
    mov edx, tag_fail_len
    call pstr
    lea rsi, [crlf]
    mov edx, 1
    call pstr
    jmp .disc

.disc:
    lea rdi, [api_tls]
    mov esi, r14d
    call tls_disconnect
    jmp .err

.close:
    mov edi, r14d
    call sys_close

.err_dns:
    lea rsi, [tag_fail]
    mov edx, tag_fail_len
    call pstr
.err:
    xor eax, eax
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Load Slack token from .env file (line: SLACK_TOKEN=value)
; Returns 0 on failure, nonzero on success.
; On success: rdi = token ptr, rsi = token length
load_env_token:
    ; Open .env
    lea rdi, [rel dotenv]
    mov esi, O_RDONLY
    xor edx, edx
    mov eax, SYS_open
    syscall
    test eax, eax
    js .let_done
    mov ebx, eax                ; fd

    ; Read
    mov edi, ebx                ; fd
    lea rsi, [envbuf]
    mov edx, 4096
    mov eax, SYS_read
    syscall
    test rax, rax
    jle .let_read_fail
    mov r12, rax                ; total bytes read
    jmp .let_close_ok

.let_read_fail:
    mov edi, ebx
    mov eax, SYS_close
    syscall
    xor eax, eax
    ret

.let_close_ok:
    mov edi, ebx
    mov eax, SYS_close
    syscall

    ; Scan envbuf line by line for "SLACK_TOKEN="
    lea r8, [envbuf]
    mov r9, r12                 ; remaining bytes
.let_line_loop:
    test r9, r9
    jz .let_done
    ; Check if this line starts with "SLACK_TOKEN="
    cmp r9, 12
    jb .let_next_line
    cmp dword [r8], 'SLAC'
    jne .let_next_line
    cmp dword [r8 + 4], 'K_TO'
    jne .let_next_line
    cmp dword [r8 + 8], 'KEN='
    jne .let_next_line
    ; Found! r8 points to "SLACK_TOKEN="
    add r8, 12                  ; skip key to get value start
    mov rdi, r8                 ; value start
    xor ecx, ecx
.let_scan_val:
    cmp rcx, r9
    jae .let_copy_val
    cmp byte [rdi + rcx], 0x0A
    je .let_copy_val
    cmp byte [rdi + rcx], 0x0D
    je .let_copy_val
    inc rcx
    jmp .let_scan_val
.let_copy_val:
    test ecx, ecx
    jz .let_next_line
    cmp ecx, 255
    jb .let_copy2
    mov ecx, 255
.let_copy2:
    mov r12, rcx                ; save length
    lea rdi, [envtoken]
    mov rsi, r8                 ; start of value
    rep movsb
    mov byte [rdi], 0
    lea rdi, [envtoken]
    mov rsi, r12
    mov eax, 1
    ret

.let_next_line:
    ; Skip to next line
    xor ecx, ecx
.let_skip:
    cmp rcx, r9
    jae .let_done
    cmp byte [r8 + rcx], 0x0A
    je .let_advance
    inc rcx
    jmp .let_skip
.let_advance:
    inc rcx
    add r8, rcx
    sub r9, rcx
    jmp .let_line_loop
.let_done:
    xor eax, eax
    ret

; Hex dump, rsi = data, edx = length
hex_dump:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rsi
    mov r12, rsi
    mov r13d, edx
    xor r14d, r14d
.hd_loop:
    cmp r14d, r13d
    jae .hd_done
    movzx eax, byte [r12 + r14]
    mov r15d, eax
    shr eax, 4
    and eax, 0x0F
    lea eax, [rax + '0']
    cmp eax, '9'
    jbe .hd_low
    add eax, 'A' - '9' - 1
.hd_low:
    mov byte [rsp + 6], al
    mov eax, r15d
    and eax, 0x0F
    lea eax, [rax + '0']
    cmp eax, '9'
    jbe .hd_hi
    add eax, 'A' - '9' - 1
.hd_hi:
    mov byte [rsp + 7], al
    lea rsi, [rsp + 6]
    mov edx, 2
    mov eax, SYS_write
    mov edi, STDOUT
    syscall
    inc r14d
    mov eax, r14d
    and eax, 0x1F
    jnz .hd_loop
    mov byte [rsp + 6], 10
    lea rsi, [rsp + 6]
    mov edx, 1
    call pstr
    jmp .hd_loop
.hd_done:
    mov byte [rsp + 6], 10
    lea rsi, [rsp + 6]
    mov edx, 1
    call pstr
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

print_banner:
    lea rsi, [banner]
    mov edx, banner_len
pstr:
    mov eax, SYS_write
    mov edi, STDOUT
    syscall
    ret

pnl:
    lea rsi, [crlf]
    mov edx, 1
    jmp pstr

pnum:
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
.l:
    dec rbx
    xor edx, edx
    div r12d
    add dl, '0'
    mov [rbx], dl
    test eax, eax
    jnz .l
    mov rsi, rbx
    lea rax, [rsp + 21]
    sub rax, rbx
    mov edx, eax
    call pstr
    add rsp, 24
    pop r12
    pop rbx
    ret