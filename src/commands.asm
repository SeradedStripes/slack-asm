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
extern delete_prefix, delete_prefix_len
extern delete_suffix, delete_suffix_len

; ============================================================
; Simple commands
; ============================================================

def_slash_cmd ping, "ping", "pong", "Returns 'pong' in response."
def_slash_cmd bing, "bing", "bong", "Returns 'bong' in response."
def_slash_cmd meow, "meow", "meoww", "Meow back at you."

; ============================================================
; Commands where the slash command trigger should be deleted after execution
; ============================================================

def_delete_cmd shameless_plug, "shameless plug", "https://stardance.hackclub.com/projects/6658", "A shameless plug."

; ============================================================
; Complex commands
; ============================================================

def_complex_cmd help, "help", "Displays this help message."

def_complex_cmd pung, "pung", "Pings a user: Get punged {user} :bleh:"

section .rodata
pung_prefix: db "Get punged "
pung_prefix_len: equ $ - pung_prefix
pung_suffix: db " :bleh:"
pung_suffix_len: equ $ - pung_suffix
section .text

pung_handler:
    mov r10, [rsp + 8]
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 512
    mov r15, r10

    ; Save remaining text (passed in rsi/edx from dispatch)
    mov r12, rsi
    mov r13d, edx

    mov r8, [r15 + handler_args.response_url]
    test r8, r8
    jnz .pung_resp_url

    ; No response_url → WS or threaded
    mov r8, [r15 + handler_args.thread_ts]
    test r8, r8
    jnz .pung_thread

    ; WS response
    lea rdi, [rsp]
    lea rsi, [rel pung_prefix]
    mov ecx, pung_prefix_len
    cld
    rep movsb
    mov rsi, r12
    mov ecx, r13d
    rep movsb
    lea rsi, [rel pung_suffix]
    mov ecx, pung_suffix_len
    rep movsb
    mov rax, rdi
    sub rax, rsp
    mov r14d, eax

    mov rdi, [r15 + handler_args.envelope_id]
    mov esi, [r15 + handler_args.envelope_id_len]
    lea rdx, [rsp]
    mov ecx, r14d
    call slack_send_response
    jmp .pung_done

.pung_thread:
    lea rdi, [rsp]
    lea rsi, [rel pung_prefix]
    mov ecx, pung_prefix_len
    cld
    rep movsb
    mov rsi, r12
    mov ecx, r13d
    rep movsb
    lea rsi, [rel pung_suffix]
    mov ecx, pung_suffix_len
    rep movsb
    mov rax, rdi
    sub rax, rsp
    mov r14d, eax

    lea rdx, [rsp]
    mov ecx, r14d
    call send_cpm_threaded
    jmp .pung_done

.pung_resp_url:
    ; Slash command: ack + POST replace_original with dynamic text
    mov rdi, [r15 + handler_args.envelope_id]
    mov esi, [r15 + handler_args.envelope_id_len]
    call slack_send_ack

    lea rdi, [rsp]
    lea rsi, [rel delete_prefix]
    mov ecx, delete_prefix_len
    cld
    rep movsb
    lea rsi, [rel pung_prefix]
    mov ecx, pung_prefix_len
    rep movsb
    mov rsi, r12
    mov ecx, r13d
    rep movsb
    lea rsi, [rel pung_suffix]
    mov ecx, pung_suffix_len
    rep movsb
    lea rsi, [rel delete_suffix]
    mov ecx, delete_suffix_len
    rep movsb

    mov rax, rdi
    sub rax, rsp
    mov r14d, eax

    mov rdi, [r15 + handler_args.response_url]
    mov esi, [r15 + handler_args.response_url_len]
    lea rdx, [rsp]
    mov ecx, r14d
    xor r8, r8
    xor r9d, r9d
    call slack_send_http_post

.pung_done:
    add rsp, 512
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

help_handler:
    mov r10, [rsp + 8]
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 512

    ; Save handler_args in callee-saved r15
    mov r15, r10

    ; Build help text into [rsp..rsp+255]
    lea rdi, [rsp]
    call build_help_table
    mov r12d, eax              ; help text length

    ; Decide reply channel
    mov r8, [r15 + handler_args.thread_ts]
    test r8, r8
    jnz .thread_ws

    ; WS response (same pattern as def_slash_cmd, keeps original command)
    mov rdi, [r15 + handler_args.envelope_id]
    mov esi, [r15 + handler_args.envelope_id_len]
    lea rdx, [rsp]
    mov ecx, r12d
    call slack_send_response
    jmp .done

.thread_ws:
    lea rdx, [rsp]
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
