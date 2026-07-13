; Slack slash command handlers
BITS 64
default rel

%define WS_TEXT 0x1
%define CMD_NAMESPACED 1

; Macro: define a simple command that replies with a canned response
; %1 = identifier prefix (e.g., ping -> str_ping, ping_handler, msg_ping)
; %2 = command name string (e.g., "ping")
; %3 = response text string (e.g., "pong")
%macro def_slash_cmd 3
  section .rodata
  str_%1: db %2
  str_%1_len: equ $ - str_%1
  msg_%1: db %3
  msg_%1_len: equ $ - msg_%1
  section .text
  global %1_handler
  %1_handler:
      mov r10, [rsp + 8]
      push rbx
      push r12
      mov r8, [r10 + handler_args.thread_ts]
      test r8, r8
      jnz .%1_thread
      mov rdi, [r10 + handler_args.envelope_id]
      mov esi, [r10 + handler_args.envelope_id_len]
      lea rdx, [rel msg_%1]
      mov ecx, msg_%1_len
      call slack_send_response
      jmp .%1_done
  .%1_thread:
      lea rdx, [rel msg_%1]
      mov ecx, msg_%1_len
      call send_cpm_threaded
  .%1_done:
      pop r12
      pop rbx
      ret
%endmacro

%macro reg_slash_cmd 1
  lea rdi, [rel str_%1]
  mov esi, str_%1_len
  lea rdx, [rel %1_handler]
  mov ecx, CMD_NAMESPACED
  call cmd_register
%endmacro

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

def_slash_cmd ping, "ping", "pong"
def_slash_cmd bing, "bing", "bong"
def_slash_cmd meow, "meow", "meoww"

section .rodata
str_help:           db "help"
str_help_len:       equ $ - str_help

msg_help_text:      db "Available commands:", 0x0A
                    db "/slack-asm help - Displays this help message.", 0x0A
                    db "/slack-asm ping - Returns 'pong' in response.", 0x0A
                    db "/slack-asm meow - Returns 'meoww' in response.", 0x0A
                    db "/slack-asm bing - Returns 'bong' in response.", 0x0A
msg_help_text_len:  equ $ - msg_help_text

resp_body_prefix: db '{"response_type":"in_channel","text":"'
resp_body_prefix_len: equ $ - resp_body_prefix
resp_body_suffix: db '"}'
resp_body_suffix_len: equ $ - resp_body_suffix

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
global cmd_register_all, help_handler

extern cmd_register
extern slack_send_response
extern slack_send_response_ephemeral
extern slack_send_response_thread
extern slack_send_http_post
extern slack_send_ack
extern bot_token, bot_token_len
extern debug_putc, debug_hexdump

cmd_register_all:
    push rbx
    reg_slash_cmd ping
    reg_slash_cmd bing
    reg_slash_cmd meow

    lea rdi, [rel str_help]
    mov esi, str_help_len
    lea rdx, [rel help_handler]
    mov ecx, CMD_NAMESPACED
    call cmd_register

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

    ; Check if response_url is available (preferred for slash commands)
    mov r8, [r10 + handler_args.response_url]
    test r8, r8
    jnz .resp_url

    ; Check for thread_ts (bot mention)
    mov r8, [r10 + handler_args.thread_ts]
    test r8, r8
    jnz .help_thread_ws

    ; Fall back to WS response for non-slash-command events
    jmp .no_thread

.resp_url:
    ; Send ack via WebSocket FIRST (must be within 3 seconds)
    mov [rsp], r10                ; save handler_args ptr (r10 is scratch)
    mov rdi, [r10 + handler_args.envelope_id]
    mov esi, [r10 + handler_args.envelope_id_len]
    call slack_send_ack
    mov r10, [rsp]                ; restore handler_args ptr

    ; Build JSON body for response_url:
    ; {"response_type":"in_channel","text":"<help>"}
    lea rdi, [rsp]

    lea rsi, [rel resp_body_prefix]
    mov ecx, resp_body_prefix_len
    cld
    rep movsb

    lea rsi, [rel msg_help_text]
    mov ecx, msg_help_text_len
    rep movsb

    lea rsi, [rel resp_body_suffix]
    mov ecx, resp_body_suffix_len
    rep movsb

    ; Calculate body length
    mov rbx, rdi
    lea rax, [rsp]
    sub rbx, rax
    mov r14d, ebx

    ; POST to response_url (URL is self-authenticating, no auth needed)
    mov rdi, [r10 + handler_args.response_url]
    mov esi, [r10 + handler_args.response_url_len]
    lea rdx, [rsp]
    mov ecx, r14d
    xor r8, r8          ; no auth value
    xor r9d, r9d        ; no auth length
    call slack_send_http_post
    jmp .done

.help_thread_ws:
    lea rdx, [rel msg_help_text]
    mov ecx, msg_help_text_len
    call send_cpm_threaded
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

; void send_cpm_threaded(const char *text, uint32_t text_len)
; rdx = text ptr, ecx = text_len
; Uses handler_args at r10 for channel_id, thread_ts, envelope_id
; Sends WS ack first, then POSTs to chat.postMessage
send_cpm_threaded:
    cld
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 512

    mov r12, rdx
    mov r13d, ecx
    mov r15, r10              ; save handler_args ptr in callee-saved r15

    ; Acknowledge envelope via WebSocket
    mov rdi, [r15 + handler_args.envelope_id]
    mov esi, [r15 + handler_args.envelope_id_len]
    call slack_send_ack

    ; Build JSON body: {"channel":"CH","text":"TEXT","thread_ts":"TS"}
    lea rdi, [rsp]

    lea rsi, [rel cpm_prefix]
    mov ecx, cpm_prefix_len
    rep movsb

    mov rsi, [r15 + handler_args.channel_id]
    mov ecx, [r15 + handler_args.channel_id_len]
    rep movsb

    lea rsi, [rel cpm_mid1]
    mov ecx, cpm_mid1_len
    rep movsb

    mov rsi, r12
    mov ecx, r13d
    rep movsb

    lea rsi, [rel cpm_mid2]
    mov ecx, cpm_mid2_len
    rep movsb

    mov rsi, [r15 + handler_args.thread_ts]
    mov ecx, [r15 + handler_args.thread_ts_len]
    rep movsb

    lea rsi, [rel cpm_suffix]
    mov ecx, cpm_suffix_len
    rep movsb

    mov rax, rdi
    sub rax, rsp
    mov r14d, eax

    ; POST to chat.postMessage
    lea rdi, [rel cpm_url]
    mov esi, cpm_url_len
    lea rdx, [rsp]
    mov ecx, r14d
    lea r8, [rel bot_token]
    mov r9d, [rel bot_token_len]
    call slack_send_http_post

    add rsp, 512
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
