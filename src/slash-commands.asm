; Slack slash command handlers
BITS 64
default rel

%define WS_TEXT 0x1
%define CMD_NAMESPACED 1

struc handler_args
    .user_len      resq 1
    .envelope_id   resq 1
    .envelope_id_len resq 1
    .thread_ts     resq 1
    .thread_ts_len resq 1
endstruc

section .rodata
str_ping:           db "ping"
str_ping_len:       equ $ - str_ping
str_help:           db "help"
str_help_len:       equ $ - str_help

msg_pong:           db "pong"
msg_pong_len:       equ $ - msg_pong

msg_help_text:      db "Available commands:", 0x0A
                    db "/slack-asm help - Displays this help message.", 0x0A
                    db "/slack-asm ping - Returns 'pong' in response.", 0x0A
msg_help_text_len:  equ $ - msg_help_text

section .text
global cmd_register_all, ping_handler, help_handler

extern cmd_register
extern slack_send_response
extern slack_send_response_ephemeral
extern slack_send_response_thread

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

    pop rbx
    ret

; ping handler, replies with "pong"
; Invoked as: /slack-asm ping [args...]
ping_handler:
    mov r10, [rsp + 8]      ; handler_args ptr (skip return addr)

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

; help handler, replies with available commands
; Invoked as: /slack-asm help
help_handler:
    mov r10, [rsp + 8]      ; handler_args ptr

    push rbx
    push r12

    mov rdi, [r10 + handler_args.envelope_id]
    mov esi, [r10 + handler_args.envelope_id_len]
    lea rdx, [rel msg_help_text]
    mov ecx, msg_help_text_len

    ; Reply in thread if invoked from one, otherwise in-channel
    mov r8, [r10 + handler_args.thread_ts]
    test r8, r8
    jz .no_thread

    mov r9d, [r10 + handler_args.thread_ts_len]
    call slack_send_response_thread
    jmp .done

.no_thread:
    call slack_send_response

.done:
    pop r12
    pop rbx
    ret
