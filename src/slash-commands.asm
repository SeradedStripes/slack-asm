; Slack slash command handlers
BITS 64
default rel

%define WS_TEXT 0x1
%define CMD_NAMESPACED 1

struc handler_args
    .user_len      resq 1
    .envelope_id   resq 1
    .envelope_id_len resq 1
endstruc

section .rodata
str_ping:           db "ping"
str_ping_len:       equ $ - str_ping

msg_pong:           db "pong"
msg_pong_len:       equ $ - msg_pong

section .text
global cmd_register_all, ping_handler

extern cmd_register
extern slack_send_response

; Register all slash command handlers
; Call once after cmd_init()
cmd_register_all:
    push rbx

    lea rdi, [rel str_ping]
    mov esi, str_ping_len
    lea rdx, [rel ping_handler]
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
