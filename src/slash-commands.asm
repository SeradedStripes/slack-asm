; Slack slash command handlers
BITS 64
default rel

%define WS_TEXT 0x1
%define CMD_NAMESPACED 1

struc handler_args
    .channel_id      resq 1
    .channel_id_len  resq 1
    .user_id_ptr     resq 1
    .user_id_len     resq 1
    .envelope_id     resq 1
    .envelope_id_len resq 1
    .thread_ts       resq 1
    .thread_ts_len   resq 1
    .response_url    resq 1
    .response_url_len resq 1
endstruc

section .rodata
str_ping:           db "ping"
str_ping_len:       equ $ - str_ping
str_help:           db "help"
str_help_len:       equ $ - str_help
str_meow:           db "meow"
str_meow_len:       equ $ - str_meow

msg_pong:           db "pong"
msg_pong_len:       equ $ - msg_pong

msg_meow:           db "meoww"
msg_meow_len:       equ $ - msg_meow

msg_help_text:      db "Available commands:", 0x0A
                    db "/slack-asm help - Displays this help message.", 0x0A
                    db "/slack-asm ping - Returns 'pong' in response.", 0x0A
                    db "/slack-asm meow - Returns 'meoww' in response.", 0x0A
msg_help_text_len:  equ $ - msg_help_text

resp_url_prefix:  db '{"response_type":"in_channel","thread_ts":"'
resp_url_prefix_len: equ $ - resp_url_prefix
resp_url_mid:     db '","text":"'
resp_url_mid_len: equ $ - resp_url_mid
resp_url_suffix:  db '"}'
resp_url_suffix_len: equ $ - resp_url_suffix

cpm_url:         db "https://slack.com/api/chat.postMessage"
cpm_url_len:     equ $ - cpm_url
cpm_prefix:      db '{"channel":"'
cpm_prefix_len:  equ $ - cpm_prefix
cpm_mid1:        db '","text":"'
cpm_mid1_len:    equ $ - cpm_mid1
cpm_mid2:        db '","thread_ts":"'
cpm_mid2_len:    equ $ - cpm_mid2
cpm_suffix:      db '"}'
cpm_suffix_len:  equ $ - cpm_suffix

section .text
global cmd_register_all, ping_handler, help_handler, meow_handler

extern cmd_register
extern slack_send_response
extern slack_send_response_ephemeral
extern slack_send_response_thread
extern slack_send_http_post
extern slack_send_ack
extern bot_token, bot_token_len
extern debug_putc, debug_hexdump

; Register all slash command handlers
; Call once after cmd_init()
cmd_register_all:
    push rbx

    lea rdi, [rel str_ping]
    mov esi, str_ping_len
    lea rdx, [rel ping_handler]
    mov ecx, CMD_NAMESPACED
    call cmd_register

    lea rdi, [rel str_help]
    mov esi, str_help_len
    lea rdx, [rel help_handler]
    mov ecx, CMD_NAMESPACED
    call cmd_register

    lea rdi, [rel str_meow]
    mov esi, str_meow_len
    lea rdx, [rel meow_handler]
    mov ecx, CMD_NAMESPACED
    call cmd_register

    pop rbx
    ret

; ping handler, replies with "pong"
; Invoked as: /slack-asm ping [args...]
ping_handler:
    mov r10, [rsp + 8]      ; handler_args ptr

    push rbx
    push r12

    mov rdi, [r10 + handler_args.envelope_id]
    mov esi, [r10 + handler_args.envelope_id_len]
    lea rdx, [rel msg_pong]
    mov ecx, msg_pong_len
    call slack_send_response

    pop r12
    pop rbx
    ret

meow_handler:
    mov r10, [rsp + 8]      ; handler_args ptr

    push rbx
    push r12

    mov rdi, [r10 + handler_args.envelope_id]
    mov esi, [r10 + handler_args.envelope_id_len]
    lea rdx, [rel msg_meow]
    mov ecx, msg_meow_len
    call slack_send_response

    pop r12
    pop rbx
    ret

; help handler, replies with available commands
; Invoked as: /slack-asm help
help_handler:
    mov r10, [rsp + 8]      ; handler_args ptr

    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 512

    mov r8, [r10 + handler_args.thread_ts]
    test r8, r8
    jz .no_thread

    ; Send ack via WebSocket FIRST (must be within 3 seconds)
    mov [rsp], r10                ; save handler_args ptr (r10 is scratch)
    mov rdi, [r10 + handler_args.envelope_id]
    mov esi, [r10 + handler_args.envelope_id_len]
    call slack_send_ack
    mov r10, [rsp]                ; restore handler_args ptr

    ; Build chat.postMessage body on stack:
    ; {"channel":"<id>","text":"<help>","thread_ts":"<ts>"}
    lea rdi, [rsp]

    lea rsi, [rel cpm_prefix]
    mov ecx, cpm_prefix_len
    cld
    rep movsb

    mov rsi, [r10 + handler_args.channel_id]
    mov ecx, [r10 + handler_args.channel_id_len]
    rep movsb

    lea rsi, [rel cpm_mid1]
    mov ecx, cpm_mid1_len
    rep movsb

    lea rsi, [rel msg_help_text]
    mov ecx, msg_help_text_len
    rep movsb

    lea rsi, [rel cpm_mid2]
    mov ecx, cpm_mid2_len
    rep movsb

    mov rsi, [r10 + handler_args.thread_ts]
    mov ecx, [r10 + handler_args.thread_ts_len]
    rep movsb

    lea rsi, [rel cpm_suffix]
    mov ecx, cpm_suffix_len
    rep movsb

    mov rbx, rdi
    lea rax, [rsp]
    sub rbx, rax
    mov r14d, ebx            ; body length

    ; POST to chat.postMessage API with bot token auth
    lea rdi, [rel cpm_url]
    mov esi, cpm_url_len
    lea rdx, [rsp]
    mov ecx, r14d
    lea r8, [rel bot_token]
    mov r9d, [rel bot_token_len]
    call slack_send_http_post
    jmp .done

.no_thread:
    mov rdi, [r10 + handler_args.envelope_id]
    mov esi, [r10 + handler_args.envelope_id_len]
    lea rdx, [rel msg_help_text]
    mov ecx, msg_help_text_len
    call slack_send_response

.done:
    add rsp, 512
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
