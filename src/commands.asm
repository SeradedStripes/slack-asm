; Command definitions for slack-asm
; All commands go here. Use macros from cmd_macros.inc to define them.
BITS 64
default rel

%include "cmd_macros.inc"

; Externs needed by handlers
extern cmd_register
extern slack_send_response
extern slack_send_http_post
extern slack_send_ack
extern send_cpm_threaded
extern help_register
extern build_help_table
extern resp_body_prefix, resp_body_prefix_len
extern resp_body_suffix, resp_body_suffix_len

; ============================================================
; Simple commands
; ============================================================

def_slash_cmd ping, "ping", "pong", "Returns 'pong' in response."
def_slash_cmd bing, "bing", "bong", "Returns 'bong' in response."
def_slash_cmd meow, "meow", "meoww", "Meow back at you."

; ============================================================
; Complex commands
; ============================================================

def_complex_cmd help, "help", "Displays this help message."

help_handler:
    mov r10, [rsp + 8]
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 512

    ; Build help text into [rsp..rsp+255]
    lea rdi, [rsp]
    call build_help_table
    mov r12d, eax              ; help text length

    ; Decide reply channel
    mov r8, [r10 + handler_args.response_url]
    test r8, r8
    jnz .resp_url
    mov r8, [r10 + handler_args.thread_ts]
    test r8, r8
    jnz .thread_ws

    ; WS response
    mov rdi, [r10 + handler_args.envelope_id]
    mov esi, [r10 + handler_args.envelope_id_len]
    lea rdx, [rsp]
    mov ecx, r12d
    call slack_send_response
    jmp .done

.resp_url:
    mov [rsp + 504], r10
    mov rdi, [r10 + handler_args.envelope_id]
    mov esi, [r10 + handler_args.envelope_id_len]
    call slack_send_ack
    mov r10, [rsp + 504]

    ; Build JSON: {"response_type":"in_channel","text":"<help>"}
    lea rdi, [rsp + 256]
    lea rsi, [rel resp_body_prefix]
    mov ecx, resp_body_prefix_len
    cld
    rep movsb

    lea rsi, [rsp]
    mov ecx, r12d
    rep movsb

    lea rsi, [rel resp_body_suffix]
    mov ecx, resp_body_suffix_len
    rep movsb

    lea rax, [rsp + 256]
    sub rdi, rax
    mov r14d, edi

    mov rdi, [r10 + handler_args.response_url]
    mov esi, [r10 + handler_args.response_url_len]
    lea rdx, [rsp + 256]
    mov ecx, r14d
    xor r8, r8
    xor r9d, r9d
    call slack_send_http_post
    jmp .done

.thread_ws:
    mov rdx, rsp
    mov ecx, r12d
    call send_cpm_threaded

.done:
    add rsp, 512
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================
; Registration
; ============================================================

extern __start_regcmds
extern __stop_regcmds

global cmd_register_all
cmd_register_all:
    push rbx
    push r12
    push r13
    lea r12, [rel __start_regcmds]
    lea r13, [rel __stop_regcmds]
.loop:
    cmp r12, r13
    jae .done
    mov rdi, [r12 + reg_entry.name_ptr]
    mov esi, [r12 + reg_entry.name_len]
    mov rdx, [r12 + reg_entry.handler]
    mov ecx, CMD_NAMESPACED
    call cmd_register
    mov rdi, [r12 + reg_entry.help_ptr]
    mov esi, [r12 + reg_entry.help_len]
    call help_register
    add r12, reg_entry_size
    jmp .loop
.done:
    pop r13
    pop r12
    pop rbx
    ret
