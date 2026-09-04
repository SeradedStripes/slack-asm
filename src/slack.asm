; slack-asm: Slack client in x86-64 assembly
BITS 64
default rel

%define SYS_read   0
%define SYS_write  1
%define SYS_open   2
%define SYS_close  3
%define SYS_nanosleep 35
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
    extern debug_putc, debug_hexdump
    extern base64_encode
extern memmem
extern cmd_init, cmd_register_all, cmd_dispatch
extern client_write_key, server_write_key
extern client_write_iv, server_write_iv
extern client_write_mac_key, server_write_mac_key

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

needle_event_callback: db "event_callback"
needle_event_callback_len: equ $ - needle_event_callback

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
key_ts:          db '"ts"'
key_ts_len:      equ $ - key_ts
dotenv:          db ".env", 0
slack_token_key: db "SLACK_TOKEN="
bot_token_key:   db "SLACK_BOT_TOKEN="
history_path:    db "/api/conversations.history"
history_path_len: equ $ - history_path

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
envbuf_size: resq 1             ; bytes read into envbuf
environ_ptr: resq 1             ; pointer to environ array from _start
bot_token:   resb 256           ; bot token from .env (xoxb-...)
bot_token_len: resd 1           ; bot token length
fallback_ts: resb 32            ; temporary buffer for API-fetched ts

global ws_ctx_ptr, ws_fd, bot_token, bot_token_len
ws_ctx_ptr: resq 1             ; WebSocket TLS context pointer for command handlers
ws_fd:      resd 1             ; WebSocket fd for command handlers

section .text
global _start

_start:
    pop rcx                     ; argc
    ; Save envp: after argv pointers + NULL terminator
    lea rax, [rsp + rcx*8 + 8]
    mov [rel environ_ptr], rax
    cmp ecx, 2
    jge .from_argv

    ; Try reading token from .env
    call load_env_token
    test eax, eax
    jnz .go_env

    ; Try reading token from environment variables
    call load_env_from_environ
    test eax, eax
    jnz .go_env_environ

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
    xor r14d, r14d              ; retry count (0 = no initial delay)
.reconnect:
    mov edi, r14d
    call sleep_backoff
    call main
    inc r14d
    jmp .reconnect

.go_env:
    mov r12, rdi                ; token ptr from load_env_token
    mov r13, rsi                ; token len
    call load_bot_token
    xor ebp, ebp
    xor r14d, r14d              ; retry count (0 = no initial delay)
    jmp .reconnect_env

.go_env_environ:
    mov r12, rdi                ; token ptr from load_env_from_environ
    mov r13, rsi                ; token len
    ; bot_token/bot_token_len already populated by load_env_from_environ
    xor ebp, ebp
    xor r14d, r14d              ; retry count (0 = no initial delay)

.reconnect_env:
    mov edi, r14d
    call sleep_backoff
    call main
    inc r14d
    jmp .reconnect_env

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

    ; Store WS context and fd for command handlers
    lea rax, [ws_tls]
    mov [rel ws_ctx_ptr], rax
    mov [rel ws_fd], r14d

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
    ; Incremental HTTP parse: if complete, exit loop
    lea r15, [recvbuf]
    mov rdi, r15
    mov esi, ebp
    call http_parse_response
    test eax, eax
    js .ws_recv_skip
    mov rax, [rel http_body_ptr]
    sub rax, r15
    add rax, [rel http_body_len]
    cmp rax, rbp
    jbe .ws_recv_done
.ws_recv_skip:
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

    ; Step 9: Init command framework and enter event loop
    call cmd_init
    call cmd_register_all

    jmp .frame_loop

.bad_ws:
    lea rsi, [tag_fail]
    mov edx, tag_fail_len
    call pstr
    mov eax, [rel http_status]
    call pnum
    call pnl
    jmp .close_ws

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
    ; Suppress RCVD log for events_api events (too noisy)
    lea rdi, [recvbuf]
    mov esi, [rel wslen]
    lea rdx, [rel needle_event_callback]
    mov ecx, needle_event_callback_len
    call memmem
    test eax, eax
    jnz .after_rcvd_log
    lea rsi, [tag_rcvd]
    mov edx, tag_rcvd_len
    call pstr
    lea rsi, [recvbuf]
    mov edx, [rel wslen]
    call pstr
    call pnl
.after_rcvd_log:
    lea rdi, [recvbuf]
    mov esi, [rel wslen]
    call cmd_dispatch
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
    ; Try parsing HTTP response so far to detect completeness
    push rbp
    lea rdi, [recvbuf]
    mov esi, ebp
    call http_parse_response
    pop rbp
    test eax, eax
    js .recv_cont
    ; Parsing succeeded: check if full body is present
    mov rax, [rel http_body_ptr]
    lea rcx, [recvbuf]
    sub rax, rcx                ; header length
    add rax, [rel http_body_len] ; total expected response length
    cmp rax, rbp
    jbe .recv_done              ; full response received
.recv_cont:
    cmp ebp, RECV_BUF_SIZE - 16384
    jb .recv
.recv_done:
    test ebp, ebp
    jz .disc

    ; Debug: dump response
    lea rsi, [recvbuf]
    mov edx, ebp
    call hex_dump

    ; Parse HTTP (may be redundant if already parsed in loop, but harmless)
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

    ; Unescape JSON: replace "\/" with "/" in-place
    lea rdi, [ws_url]
    xor ecx, ecx
    xor edx, edx
.unesc_loop:
    cmp ecx, r13d
    jae .unesc_done
    mov al, [rdi + rcx]
    cmp al, '\'
    jne .unesc_copy
    mov eax, ecx
    inc eax
    cmp eax, r13d
    jae .unesc_copy
    cmp byte [rdi + rcx + 1], '/'
    jne .unesc_copy
    inc ecx
    mov al, [rdi + rcx]
.unesc_copy:
    mov [rdi + rdx], al
    inc ecx
    inc edx
    jmp .unesc_loop
.unesc_done:
    mov byte [rdi + rdx], 0
    mov r13d, edx

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
    mov [rel envbuf_size], rax  ; save for later scans
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

; void load_bot_token(void)
; Scans envbuf for SLACK_BOT_TOKEN= and stores in bot_token/bot_token_len.
load_bot_token:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r8, [rel envbuf_size]
    test r8, r8
    jz .lbt_done

    lea rbx, [envbuf]
    mov r9, r8
.lbt_loop:
    test r9, r9
    jz .lbt_done
    cmp r9, 16
    jb .lbt_next
    cmp dword [rbx], 'SLAC'
    jne .lbt_next
    push rdi
    push rsi
    mov dil, 'A'
    call debug_putc
    pop rsi
    pop rdi
    cmp dword [rbx + 4], 'K_BO'
    jne .lbt_next
    push rdi
    push rsi
    mov dil, 'B'
    call debug_putc
    pop rsi
    pop rdi
    cmp dword [rbx + 8], 'T_TO'
    jne .lbt_next
    push rdi
    push rsi
    mov dil, 'C'
    call debug_putc
    pop rsi
    pop rdi
    cmp word [rbx + 13], 'EN'
    jne .lbt_next
    push rdi
    push rsi
    mov dil, 'D'
    call debug_putc
    pop rsi
    pop rdi
    cmp byte [rbx + 15], '='
    jne .lbt_next
    push rdi
    push rsi
    mov dil, '!'
    call debug_putc
    pop rsi
    pop rdi
    ; Found! skip key (16 bytes)
    lea r8, [rbx + 16]
    mov rdi, r8
    xor ecx, ecx
.lbt_scan:
    cmp rcx, r9
    jae .lbt_copy
    cmp byte [rdi + rcx], 0x0A
    je .lbt_copy
    cmp byte [rdi + rcx], 0x0D
    je .lbt_copy
    cmp byte [rdi + rcx], 0x00
    je .lbt_copy
    inc rcx
    jmp .lbt_scan
.lbt_copy:
    test ecx, ecx
    jz .lbt_done
    cmp ecx, 255
    jb .lbt_copy2
    mov ecx, 255
.lbt_copy2:
    mov [rel bot_token_len], ecx
    lea rdi, [bot_token]
    mov rsi, r8
    rep movsb
    mov byte [rdi], 0
.lbt_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.lbt_next:
    xor ecx, ecx
.lbt_skip:
    cmp rcx, r9
    jae .lbt_done
    cmp byte [rbx + rcx], 0x0A
    je .lbt_advance
    inc rcx
    jmp .lbt_skip
.lbt_advance:
    inc rcx
    add rbx, rcx
    sub r9, rcx
    jmp .lbt_loop

; Load SLACK_TOKEN and SLACK_BOT_TOKEN from process environment
; Scans the environ pointer array saved by _start.
; Returns: eax=1 success (rdi=envtoken, rsi=len), eax=0 failure
load_env_from_environ:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r15, [rel environ_ptr]
    test r15, r15
    jz .lfe_fail

    mov rbx, r15                 ; save environ base for phase 2
    xor r12d, r12d              ; r12 = token length (0 = not found)

    ; Phase 1: find SLACK_TOKEN=
.lfe_scan_token:
    mov r13, [r15]
    test r13, r13
    jz .lfe_scan_bot

    cmp dword [r13], 'SLAC'
    jne .lfe_next_token
    cmp dword [r13 + 4], 'K_TO'
    jne .lfe_next_token
    cmp dword [r13 + 8], 'KEN='
    jne .lfe_next_token

    ; Found SLACK_TOKEN=, copy value to envtoken
    lea r8, [r13 + 12]
    xor ecx, ecx
.lfe_tlen:
    cmp byte [r8 + rcx], 0
    je .lfe_tcopy
    inc ecx
    jmp .lfe_tlen
.lfe_tcopy:
    test ecx, ecx
    jz .lfe_next_token
    cmp ecx, 255
    jbe .lfe_tcopy2
    mov ecx, 255
.lfe_tcopy2:
    mov r12d, ecx
    cld
    lea rdi, [envtoken]
    mov rsi, r8
    rep movsb
    mov byte [rdi], 0

.lfe_next_token:
    add r15, 8
    jmp .lfe_scan_token

.lfe_scan_bot:
    mov r15, rbx
.lfe_bot_loop:
    mov r13, [r15]
    test r13, r13
    jz .lfe_done

    cmp dword [r13], 'SLAC'
    jne .lfe_next_bot
    cmp dword [r13 + 4], 'K_BO'
    jne .lfe_next_bot
    cmp dword [r13 + 8], 'T_TO'
    jne .lfe_next_bot
    cmp word [r13 + 12], 'KE'
    jne .lfe_next_bot
    cmp byte [r13 + 14], 'N'
    jne .lfe_next_bot
    cmp byte [r13 + 15], '='
    jne .lfe_next_bot

    lea r8, [r13 + 16]
    xor ecx, ecx
.lfe_blen:
    cmp byte [r8 + rcx], 0
    je .lfe_bcopy
    inc ecx
    jmp .lfe_blen
.lfe_bcopy:
    test ecx, ecx
    jz .lfe_next_bot
    cmp ecx, 255
    jbe .lfe_bcopy2
    mov ecx, 255
.lfe_bcopy2:
    mov [rel bot_token_len], ecx
    cld
    lea rdi, [bot_token]
    mov rsi, r8
    rep movsb
    mov byte [rdi], 0

.lfe_next_bot:
    add r15, 8
    jmp .lfe_bot_loop

.lfe_done:
    test r12d, r12d
    jz .lfe_fail
    lea rdi, [envtoken]
    mov esi, r12d
    mov eax, 1
    jmp .lfe_ret

.lfe_fail:
    xor eax, eax
.lfe_ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
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

; int slack_send_http_post(const char *url, uint32_t url_len,
;                          const char *body, uint32_t body_len,
;                          const char *auth_value, uint32_t auth_value_len)
; Makes HTTPS POST to url with body as JSON payload.
; If auth_value is non-NULL, adds Authorization: Bearer <auth_value> header.
; Uses api_tls context (safe since main WS path uses ws_tls).
; Returns 0 on success, -1 on error.
global slack_send_http_post
slack_send_http_post:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 256

    ; Save args
    mov rbx, rdi          ; url
    mov r12d, esi         ; url_len
    mov r13, rdx          ; body
    mov r14d, ecx         ; body_len
    mov [rsp + 56], r8    ; auth_value ptr (NULL = no auth) — safe from URL parsing
    mov [rsp + 48], r9d   ; auth_value_len

    ; Save TLS keys (tls_connect will overwrite them)
    lea rdi, [rsp + 64]
    lea rsi, [client_write_mac_key]
    mov rcx, 32
    cld
    rep movsb
    lea rsi, [server_write_mac_key]
    mov rcx, 32
    rep movsb
    lea rsi, [client_write_key]
    mov rcx, 16
    rep movsb
    lea rsi, [server_write_key]
    mov rcx, 16
    rep movsb
    lea rsi, [client_write_iv]
    mov rcx, 4
    rep movsb
    lea rsi, [server_write_iv]
    mov rcx, 4
    rep movsb

    ; URL must start with "http" (accept both https:// and JSON-escaped https:\/\/
    cmp r12d, 6
    jb .shp_err
    cmp dword [rbx], 'http'
    jne .shp_err

    ; Skip past "http" and any "s"
    lea r15, [rbx + 4]
    mov ebp, r12d
    sub ebp, 4
    jz .shp_err
    cmp byte [r15], 's'
    jne .shp_after_proto
    inc r15
    dec ebp
    jz .shp_err

    ; Find host start: skip past "://" or ":\/\/"
.shp_after_proto:
    xor ecx, ecx           ; slash count (need 2)
.shp_find_slashes:
    cmp ecx, 2
    jae .shp_host_start
    test ebp, ebp
    jle .shp_err
    mov al, [r15]
    cmp al, '/'
    je .shp_slash_found
    cmp al, 0x5C           ; JSON-escaped backslash before /
    jne .shp_not_slash
    inc r15
    dec ebp
    test ebp, ebp
    jle .shp_err
    inc r15
    dec ebp
    inc ecx
    jmp .shp_find_slashes
.shp_slash_found:
    inc r15
    dec ebp
    inc ecx
    jmp .shp_find_slashes
.shp_not_slash:
    xor ecx, ecx
    inc r15
    dec ebp
    jmp .shp_find_slashes
.shp_host_start:
    ; r15 = first char of host, ebp = remaining length
    mov [rsp], r15         ; host ptr
    xor ecx, ecx           ; host length counter
    mov r12, r15           ; save host start for path scan later
.shp_host_scan:
    cmp ecx, ebp
    jae .shp_host_end
    cmp byte [r15 + rcx], '/'
    je .shp_host_end
    cmp byte [r15 + rcx], 0x5C   ; \/ in path
    je .shp_host_end
    inc ecx
    jmp .shp_host_scan
.shp_host_end:
    test ecx, ecx
    jz .shp_err
    mov [rsp + 8], ecx     ; host len

    ; Path starts at the '/', so find it
    lea rax, [r15 + rcx]   ; path ptr (points to '/' or '\')
    mov [rsp + 16], rax
    ; Path length = remaining - host_len
    mov eax, ebp
    sub eax, ecx
    mov [rsp + 24], eax

    ; DNS resolve
    mov rdi, [rsp]
    mov esi, [rsp + 8]
    call dns_resolve
    test eax, eax
    jz .shp_err
    mov [rsp + 28], eax    ; IP

    ; TCP socket
    mov edi, 2
    mov esi, 1
    xor edx, edx
    call sys_socket
    test eax, eax
    js .shp_err
    mov [rsp + 32], eax    ; fd

    ; TCP connect port 443
    lea rdi, [sockaddr]
    mov esi, 443
    mov edx, [rsp + 28]
    call make_sockaddr_in
    mov edi, [rsp + 32]
    lea rsi, [sockaddr]
    mov edx, 16
    call sys_connect
    test eax, eax
    jnz .shp_close

    ; TLS handshake
    lea rdi, [api_tls]
    mov esi, [rsp + 32]
    mov rdx, [rsp]
    mov ecx, [rsp + 8]
    call tls_connect
    test eax, eax
    jnz .shp_close

    ; Build HTTP POST request line manually (unescape \/ in path)
    lea rdi, [reqbuf]
    lea rsi, [m_post]
    mov ecx, m_post_len
    cld
    rep movsb
    mov byte [rdi], ' '
    inc rdi

    ; Copy path, unescaping \/ to /
    mov rsi, [rsp + 16]    ; path ptr (may contain \/)
    mov ecx, [rsp + 24]    ; path len
.shp_copy_path:
    jecxz .shp_path_done
    lodsb
    cmp al, 0x5C           ; backslash (JSON escape before /)
    jne .shp_path_put
    dec ecx
    jecxz .shp_path_done
    lodsb                  ; take the char after backslash
.shp_path_put:
    stosb
    dec ecx
    jmp .shp_copy_path
.shp_path_done:

    mov dword [rdi], ' HT'
    mov word [rdi + 3], 'TP'
    mov byte [rdi + 5], '/'
    mov byte [rdi + 6], '1'
    mov byte [rdi + 7], '.'
    mov byte [rdi + 8], '1'
    mov word [rdi + 9], 0x0A0D
    add rdi, 11

    ; Calculate bytes written for request line
    lea rax, [reqbuf]
    sub rdi, rax
    mov ebx, edi

    ; Host header
    lea rdi, [reqbuf + ebx]
    lea rsi, [h_host]
    mov edx, h_host_len
    mov rcx, [rsp]
    mov r8d, [rsp + 8]
    call http_add_header
    add ebx, eax

    ; Content-Type header
    lea rdi, [reqbuf + ebx]
    lea rsi, [h_ct]
    mov edx, h_ct_len
    lea rcx, [ct_json]
    mov r8d, ct_json_len
    call http_add_header
    add ebx, eax

    ; Authorization header (if auth_value provided)
    cmp qword [rsp + 56], 0
    je .shp_no_auth

    ; Build "Bearer <token>" in ws_url buffer
    mov byte [ws_url], 'B'
    mov byte [ws_url + 1], 'e'
    mov byte [ws_url + 2], 'a'
    mov byte [ws_url + 3], 'r'
    mov byte [ws_url + 4], 'e'
    mov byte [ws_url + 5], 'r'
    mov byte [ws_url + 6], ' '
    lea rdi, [ws_url + 7]
    mov rsi, [rsp + 56]       ; auth_value ptr
    mov ecx, [rsp + 48]       ; auth_value_len
    cld
    rep movsb
    mov ebp, [rsp + 48]
    add ebp, 7                ; auth value total = 7 + token_len

    lea rdi, [reqbuf + ebx]
    lea rsi, [h_auth]
    mov edx, h_auth_len
    lea rcx, [ws_url]
    mov r8d, ebp
    call http_add_header
    add ebx, eax

.shp_no_auth:

    ; Content-Length header (manual, value is variable)
    lea rdi, [reqbuf + ebx]
    lea rsi, [h_clen]
    mov ecx, h_clen_len
    cld
    rep movsb
    mov al, ':'
    stosb
    mov al, ' '
    stosb

    ; Convert body_len (r14d) to decimal at [rsp + 40]
    mov eax, r14d
    lea r12, [rsp + 40 + 10]
    mov byte [r12], 0
    mov ecx, 10
.shp_cl_conv:
    dec r12
    xor edx, edx
    div ecx
    add dl, '0'
    mov [r12], dl
    test eax, eax
    jnz .shp_cl_conv

    mov rsi, r12
    lea rax, [rsp + 40 + 10]
    sub rax, r12
    mov ecx, eax
    rep movsb
    mov ax, 0x0A0D
    stosw

    ; Calc position in reqbuf
    lea rax, [reqbuf]
    sub rdi, rax
    mov ebx, edi

    ; Finish headers
    lea rdi, [reqbuf + ebx]
    call http_finish_headers
    add ebx, eax

    ; Body
    mov rsi, r13
    mov ecx, r14d
    lea rdi, [reqbuf + ebx]
    rep movsb
    add ebx, r14d

    ; TLS send
    lea rdi, [api_tls]
    mov esi, [rsp + 32]
    mov edx, TLS_APPLICATION_DATA
    lea rcx, [reqbuf]
    mov r8d, ebx
    call tls_send
    test rax, rax
    js .shp_disconnect

    ; Read response (discard, just need success)
.shp_recv:
    lea rdi, [api_tls]
    mov esi, [rsp + 32]
    lea rdx, [rtype]
    lea rcx, [recvbuf]
    lea r8, [rlen]
    call tls_recv
    test eax, eax
    jnz .shp_close

.shp_disconnect:
    lea rdi, [api_tls]
    mov esi, [rsp + 32]
    call tls_disconnect
    xor eax, eax
    jmp .shp_done

.shp_close:
    mov edi, [rsp + 32]
    call sys_close

.shp_err:
    mov eax, -1

.shp_done:
    ; Restore TLS keys
    lea rsi, [rsp + 64]
    lea rdi, [client_write_mac_key]
    mov rcx, 32
    cld
    rep movsb
    lea rdi, [server_write_mac_key]
    mov rcx, 32
    rep movsb
    lea rdi, [client_write_key]
    mov rcx, 16
    rep movsb
    lea rdi, [server_write_key]
    mov rcx, 16
    rep movsb
    lea rdi, [client_write_iv]
    mov rcx, 4
    rep movsb
    lea rdi, [server_write_iv]
    mov rcx, 4
    rep movsb

    add rsp, 256
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; int slack_fetch_channel_ts(const char *channel_id, uint32_t channel_id_len)
; Calls conversations.history API using bot_token, returns latest message ts
; in fallback_ts buffer. Returns ts length (0 on failure).
global slack_fetch_channel_ts, fallback_ts
slack_fetch_channel_ts:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 152

    mov r12, rdi                ; channel_id ptr
    mov r13d, esi               ; channel_id len

    ; Save shared TLS BSS keys (will be overwritten by tls_connect below)
    lea rdi, [rsp + 48]
    lea rsi, [client_write_mac_key]
    mov rcx, 32
    cld
    rep movsb
    lea rsi, [server_write_mac_key]
    mov rcx, 32
    rep movsb
    lea rsi, [client_write_key]
    mov rcx, 16
    rep movsb
    lea rsi, [server_write_key]
    mov rcx, 16
    rep movsb
    lea rsi, [client_write_iv]
    mov rcx, 4
    rep movsb
    lea rsi, [server_write_iv]
    mov rcx, 4
    rep movsb

    ; Check bot_token is available
    mov eax, [rel bot_token_len]
    test eax, eax
    jnz .bt_ok
    jmp .sft_err
.bt_ok:

    ; DNS resolve slack.com
    lea rdi, [api_host]
    mov esi, api_host_len
    call dns_resolve
    test eax, eax
    jz .sft_err
    mov [rsp], eax              ; IP

    ; Socket
    mov edi, AF_INET
    mov esi, SOCK_STREAM
    xor edx, edx
    call sys_socket
    test eax, eax
    js .sft_err
    mov [rsp + 4], eax          ; fd

    ; Connect
    lea rdi, [sockaddr]
    mov esi, 443
    mov edx, [rsp]
    call make_sockaddr_in
    mov edi, [rsp + 4]
    lea rsi, [sockaddr]
    mov edx, 16
    call sys_connect
    test eax, eax
    jnz .sft_close

    ; TLS connect
    lea rdi, [api_tls]
    mov esi, [rsp + 4]
    lea rdx, [api_host]
    mov ecx, api_host_len
    call tls_connect
    test eax, eax
    jnz .sft_close

    ; ---- Build POST request to /api/conversations.history ----
    xor r14d, r14d              ; bytes written

    ; Request line: POST /api/conversations.history HTTP/1.1
    lea rdi, [reqbuf]
    lea rsi, [m_post]
    mov edx, m_post_len
    lea rcx, [history_path]
    mov r8d, history_path_len
    call http_start_request
    mov r14d, eax

    ; Host header
    lea rdi, [reqbuf + r14]
    lea rsi, [h_host]
    mov edx, h_host_len
    lea rcx, [api_host]
    mov r8d, api_host_len
    call http_add_header
    add r14d, eax

    ; Content-Type: application/json
    lea rdi, [reqbuf + r14]
    lea rsi, [h_ct]
    mov edx, h_ct_len
    lea rcx, [ct_json]
    mov r8d, ct_json_len
    call http_add_header
    add r14d, eax

    ; Authorization: Bearer <bot_token>
    mov byte [ws_url], 'B'
    mov byte [ws_url + 1], 'e'
    mov byte [ws_url + 2], 'a'
    mov byte [ws_url + 3], 'r'
    mov byte [ws_url + 4], 'e'
    mov byte [ws_url + 5], 'r'
    mov byte [ws_url + 6], ' '
    lea rdi, [ws_url + 7]
    lea rsi, [bot_token]
    mov ecx, [rel bot_token_len]
    cld
    rep movsb
    mov ebp, [rel bot_token_len]
    add ebp, 7                  ; auth value length = 7 + bot_token_len

    lea rdi, [reqbuf + r14]
    lea rsi, [h_auth]
    mov edx, h_auth_len
    lea rcx, [ws_url]
    mov r8d, ebp
    call http_add_header
    add r14d, eax

    ; Accept: */*
    lea rdi, [reqbuf + r14]
    lea rsi, [h_accept]
    mov edx, h_accept_len
    lea rcx, [v_accept]
    mov r8d, v_accept_len
    call http_add_header
    add r14d, eax

    ; Save channel_id ptr/len to stack for body building later
    mov [rsp + 8], r12          ; channel_id ptr
    mov [rsp + 16], r13d        ; channel_id len

    ; Body length = 12 + channel_id_len + 12
    lea ebx, [r13d + 24]
    mov [rsp + 20], ebx         ; body_len

    ; Content-Length header (manual)
    lea rdi, [reqbuf + r14]
    lea rsi, [h_clen]
    mov ecx, h_clen_len
    cld
    rep movsb
    mov byte [rdi], ':'
    inc rdi
    mov byte [rdi], ' '
    inc rdi
    mov eax, ebx
    lea r15, [rsp + 30 + 10]
    mov byte [r15], 0
    mov ecx, 10
.sft_cl_conv:
    dec r15
    xor edx, edx
    div ecx
    add dl, '0'
    mov [r15], dl
    test eax, eax
    jnz .sft_cl_conv
    mov rsi, r15
    lea rax, [rsp + 30 + 10]
    sub rax, r15
    mov ecx, eax
    rep movsb
    mov ax, 0x0A0D
    stosw
    lea rax, [reqbuf]
    sub rdi, rax
    mov r14d, edi

    ; Finish headers
    lea rdi, [reqbuf + r14]
    call http_finish_headers
    add r14d, eax

    ; Body: {"channel":"<id>","limit":1}
    mov r12, [rsp + 8]          ; restore channel_id ptr
    mov r13d, [rsp + 16]        ; restore channel_id len
    lea rdi, [reqbuf + r14]
    mov dword [rdi], '{"ch'
    mov dword [rdi + 4], 'anne'
    mov word [rdi + 8], 'l"'
    mov byte [rdi + 10], ':'
    mov byte [rdi + 11], '"'
    add rdi, 12
    mov rsi, r12                ; channel_id
    mov ecx, r13d
    rep movsb
    mov byte [rdi], '"'
    mov byte [rdi + 1], ','
    mov byte [rdi + 2], '"'
    add rdi, 3
    mov dword [rdi], 'limi'
    mov byte [rdi + 4], 't'
    mov byte [rdi + 5], '"'
    mov byte [rdi + 6], ':'
    mov byte [rdi + 7], '1'
    mov byte [rdi + 8], '}'
    add rdi, 9
    lea rax, [reqbuf]
    sub rdi, rax
    mov r14d, edi

    ; TLS send
    lea rdi, [api_tls]
    mov esi, [rsp + 4]
    mov edx, TLS_APPLICATION_DATA
    lea rcx, [reqbuf]
    mov r8d, r14d
    call tls_send
    test rax, rax
    js .sft_disconnect

    ; ---- Receive response ----
    xor ebp, ebp
.sft_recv:
    lea rdi, [api_tls]
    mov esi, [rsp + 4]
    lea rdx, [rtype]
    lea rcx, [reqbuf + rbp]
    lea r8, [rlen]
    call tls_recv
    test eax, eax
    jnz .sft_disconnect
    cmp byte [rtype], TLS_APPLICATION_DATA
    jne .sft_recv_done
    mov eax, [rlen]
    test eax, eax
    jz .sft_recv_done
    add ebp, eax
    push rbp
    lea rdi, [reqbuf]
    mov esi, ebp
    call http_parse_response
    pop rbp
    test eax, eax
    js .sft_recv_cont
    mov rax, [rel http_body_ptr]
    lea rcx, [reqbuf]
    sub rax, rcx
    add rax, [rel http_body_len]
    cmp rax, rbp
    jbe .sft_recv_done
.sft_recv_cont:
    cmp ebp, RECV_BUF_SIZE - 16384
    jb .sft_recv
.sft_recv_done:

    ; Parse HTTP
    lea rdi, [reqbuf]
    mov esi, ebp
    call http_parse_response
    test eax, eax
    js .sft_disconnect

    ; Check status 200
    cmp dword [rel http_status], 200
    jne .sft_disconnect

    ; Find "ts" in JSON body
    mov rdi, [rel http_body_ptr]
    mov rsi, [rel http_body_len]
    lea rdx, [key_ts]
    mov ecx, key_ts_len
    call json_get_str
    test rax, rax
    jz .sft_disconnect
    mov r12, rax
    mov r13d, edx
    cmp r13d, 31
    jb .sft_copy_ts
    mov r13d, 31
.sft_copy_ts:
    lea rdi, [fallback_ts]
    mov rsi, r12
    mov ecx, r13d
    cld
    rep movsb
    mov byte [rdi], 0
    mov eax, r13d               ; return ts length
    push rax
    lea rdi, [api_tls]
    mov esi, [rsp + 12]         ; fd (adjusted for push)
    call tls_disconnect
    pop rax
    jmp .sft_done

.sft_disconnect:
    lea rdi, [api_tls]
    mov esi, [rsp + 4]
    call tls_disconnect
    xor eax, eax
    jmp .sft_done

.sft_close:
    mov edi, [rsp + 4]
    call sys_close

.sft_err:
    xor eax, eax

.sft_done:
    push rax                    ; save return value
    lea rsi, [rsp + 56]         ; saved keys (after push: rsp+8 = old rsp, +48 = keys)
    lea rdi, [client_write_mac_key]
    mov rcx, 32
    cld
    rep movsb
    lea rdi, [server_write_mac_key]
    mov rcx, 32
    rep movsb
    lea rdi, [client_write_key]
    mov rcx, 16
    rep movsb
    lea rdi, [server_write_key]
    mov rcx, 16
    rep movsb
    lea rdi, [client_write_iv]
    mov rcx, 4
    rep movsb
    lea rdi, [server_write_iv]
    mov rcx, 4
    rep movsb
    pop rax                     ; restore return value
    add rsp, 152
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

; Sleep for edi seconds using nanosleep
sleep_seconds:
    sub rsp, 16
    mov [rsp], edi
    mov qword [rsp + 8], 0
    mov rdi, rsp
    xor esi, esi
    mov eax, SYS_nanosleep
    syscall
    add rsp, 16
    ret

; Exponential backoff: sleep for 1 << (edi - 1) seconds, capped at 30
; edi = retry count (0 = return immediately)
sleep_backoff:
    test edi, edi
    jz .sb_done
    mov eax, 1
    dec edi
    mov ecx, edi
    shl eax, cl
    cmp eax, 30
    jbe .sb_ok
    mov eax, 30
.sb_ok:
    mov edi, eax
    call sleep_seconds
.sb_done:
    ret