; Slack slash command framework (utilities and constants)
BITS 64
default rel

%include "cmd_macros.inc"

section .rodata
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

section .bss
help_table: resb help_entry_size * MAX_CMDS
help_count: resd 1

section .text
global send_cpm_threaded
global help_register, build_help_table
global resp_body_prefix, resp_body_prefix_len
global resp_body_suffix, resp_body_suffix_len

extern slack_send_ack
extern slack_send_http_post
extern bot_token, bot_token_len

; Append a help entry to help_table.
; rdi = text pointer, esi = text length
help_register:
    push rbx
    mov ebx, [rel help_count]
    cmp ebx, MAX_CMDS
    jae .hr_done
    shl ebx, 4
    lea rcx, [rel help_table]
    mov [rcx + rbx], rdi
    mov [rcx + rbx + 8], esi
    inc dword [rel help_count]
.hr_done:
    pop rbx
    ret

; Concatenate all help_table entries into a buffer.
; rdi = destination buffer
; Returns eax = total bytes written
build_help_table:
    push r15
    push rdi
    lea r15, [rel help_table]
    xor ebx, ebx
.bht_loop:
    cmp ebx, [rel help_count]
    jae .bht_done
    push rbx
    shl ebx, 4
    mov rsi, [r15 + rbx]
    mov ecx, [r15 + rbx + 8]
    pop rbx
    rep movsb
    inc ebx
    jmp .bht_loop
.bht_done:
    pop rax
    sub rdi, rax
    mov eax, edi
    pop r15
    ret

; void send_cpm_threaded(const char *text, uint32_t text_len)
; rdx = text ptr, ecx = text_len
; Uses handler_args at r10 for channel_id, thread_ts, envelope_id
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
    mov r15, r10

    mov rdi, [r15 + handler_args.envelope_id]
    mov esi, [r15 + handler_args.envelope_id_len]
    call slack_send_ack

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
