; Slash command framework for Slack Socket Mode
BITS 64
default rel

%define MAX_CMDS 16
%define CMD_DIRECT      0
%define CMD_NAMESPACED  1
%define WS_TEXT         0x1

struc cmd_entry
    .name_ptr resq 1
    .name_len resd 1
    .handler  resq 1
    .flags    resd 1
endstruc

struc handler_args
    .user_len      resq 1
    .envelope_id   resq 1
    .envelope_id_len resq 1
endstruc

section .rodata
str_type_slash:     db "slash_commands"
str_type_slash_len: equ $ - str_type_slash

namespace_prefix:    db "/slack-asm"
namespace_prefix_len: equ $ - namespace_prefix
escaped_prefix:      db "\/slack-asm"
escaped_prefix_len:  equ $ - escaped_prefix

key_type:           db '"type"'
key_type_len:       equ $ - key_type
key_command:        db '"command"'
key_command_len:    equ $ - key_command
key_text:           db '"text"'
key_text_len:       equ $ - key_text
key_channel:        db '"channel_id"'
key_channel_len:    equ $ - key_channel
key_user:           db '"user_id"'
key_user_len:       equ $ - key_user
key_envelope_id:    db '"envelope_id"'
key_envelope_id_len: equ $ - key_envelope_id

resp_prefix:  db '{"envelope_id":"'
resp_prefix_len:  equ $ - resp_prefix
resp_middle:  db '","payload":{"text":"'
resp_middle_len:  equ $ - resp_middle
resp_suffix:  db '"}}'
resp_suffix_len:  equ $ - resp_suffix

section .bss
cmd_table:  resb cmd_entry_size * MAX_CMDS
cmd_count:  resd 1

section .text
global cmd_init, cmd_register, cmd_dispatch, slack_send_response

extern json_get_str
extern ws_send_frame
extern ws_ctx_ptr, ws_fd
extern debug_putc
extern debug_hexdump

; void cmd_init(void)
cmd_init:
    mov dword [rel cmd_count], 0
    ret

; int cmd_register(const char *name, uint32_t name_len,
;                  void *handler, int flags)
; rdi = name ptr, esi = name len, rdx = handler fn ptr, ecx = flags
; Returns 0 on success, -1 if table full
cmd_register:
    push rbx
    push rdx

    mov eax, [rel cmd_count]
    cmp eax, MAX_CMDS
    jae .full

    mov r8d, ecx

    mov ecx, cmd_entry_size
    mul ecx
    lea rbx, [rel cmd_table + rax]

    pop rdx
    mov [rbx + cmd_entry.name_ptr], rdi
    mov [rbx + cmd_entry.name_len], esi
    mov [rbx + cmd_entry.handler], rdx
    mov [rbx + cmd_entry.flags], r8d

    inc dword [rel cmd_count]
    xor eax, eax
    pop rbx
    ret

.full:
    or eax, -1
    add rsp, 8
    pop rbx
    ret

; int cmd_dispatch(const char *json, uint32_t json_len)
; rdi = json ptr, esi = json len
; Returns 0 if dispatched, 1 if not a slash command, -1 on error
cmd_dispatch:
    push r12
    push r13
    push r14
    push r15
    push rbx
    sub rsp, 80

    mov r12, rdi
    mov r13d, esi

    ; Check type field
    mov rdi, r12
    mov esi, r13d
    lea rdx, [rel key_type]
    mov ecx, key_type_len
    call json_get_str
    test rax, rax
    jz .not_cmd

    cmp edx, str_type_slash_len
    jne .not_cmd

    push rsi
    push rdi
    mov rsi, rax
    lea rdi, [rel str_type_slash]
    mov ecx, str_type_slash_len
    cld
    repe cmpsb
    pop rdi
    pop rsi
    jne .not_cmd

    ; Extract command name
    mov rdi, r12
    mov esi, r13d
    lea rdx, [rel key_command]
    mov ecx, key_command_len
    call json_get_str
    test rax, rax
    jz .parse_err
    mov [rsp], rax
    mov [rsp + 8], edx

    ; Extract text (optional)
    mov rdi, r12
    mov esi, r13d
    lea rdx, [rel key_text]
    mov ecx, key_text_len
    call json_get_str
    mov [rsp + 16], rax
    mov [rsp + 24], edx

    ; Extract channel_id
    mov rdi, r12
    mov esi, r13d
    lea rdx, [rel key_channel]
    mov ecx, key_channel_len
    call json_get_str
    test rax, rax
    jz .parse_err
    mov [rsp + 32], rax
    mov [rsp + 40], edx

    ; Extract user_id (optional)
    mov rdi, r12
    mov esi, r13d
    lea rdx, [rel key_user]
    mov ecx, key_user_len
    call json_get_str
    mov [rsp + 48], rax
    mov [rsp + 56], edx

    ; Extract envelope_id
    mov rdi, r12
    mov esi, r13d
    lea rdx, [rel key_envelope_id]
    mov ecx, key_envelope_id_len
    call json_get_str
    mov [rsp + 64], rax
    mov [rsp + 72], edx

    ; Determine dispatch mode: check if command is the namespace prefix
    ; (allow JSON-escaped "\/" prefix)
    mov eax, [rsp + 8]
    cmp eax, namespace_prefix_len
    je .check_ns_prefix
    cmp eax, escaped_prefix_len
    jne .direct_mode
.check_escaped:
    mov rdi, [rsp]
    lea rsi, [rel escaped_prefix]
    mov ecx, escaped_prefix_len
    cld
    repe cmpsb
    je .ns_mode
    jmp .direct_mode
.check_ns_prefix:
    mov rdi, [rsp]
    lea rsi, [rel namespace_prefix]
    mov ecx, namespace_prefix_len
    cld
    repe cmpsb
    jne .check_escaped

    ; ---- Namespaced dispatch (/slack-asm <subcommand>) ----
.ns_mode:
    mov dil, 'N'
    call debug_putc
    mov rbx, [rsp + 16]          ; text ptr
    test rbx, rbx
    jz .not_cmd
    mov r14d, [rsp + 24]         ; text len
    test r14d, r14d
    jz .not_cmd

    ; Find first word in text (the subcommand name)
    xor ebp, ebp
.ns_scan:
    cmp ebp, r14d
    jae .ns_word
    cmp byte [rbx + rbp], ' '
    je .ns_word
    inc ebp
    jmp .ns_scan
.ns_word:
    test ebp, ebp
    jz .not_cmd

    ; Look up subcommand in table (must be CMD_NAMESPACED)
    xor r15d, r15d
    mov r14d, [rel cmd_count]
    test r14d, r14d
    jz .not_cmd

.ns_loop:
    cmp r15d, r14d
    jae .not_cmd

    mov eax, r15d
    mov ecx, cmd_entry_size
    mul ecx
    lea r12, [rel cmd_table + rax]

    cmp dword [r12 + cmd_entry.flags], CMD_NAMESPACED
    jne .ns_next

    mov eax, [r12 + cmd_entry.name_len]
    cmp eax, ebp
    jne .ns_next

    mov rdi, [r12 + cmd_entry.name_ptr]
    mov rsi, rbx
    mov ecx, ebp
    cld
    repe cmpsb
    je .ns_found

.ns_next:
    inc r15d
    jmp .ns_loop

.ns_found:
    mov dil, 'F'
    call debug_putc
    ; Calculate remaining text after the subcommand name
    mov rsi, [rsp + 16]
    mov r14d, [rsp + 24]
    add rsi, rbp
    sub r14d, ebp
.ns_skip:
    test r14d, r14d
    jz .ns_call
    cmp byte [rsi], ' '
    jne .ns_call
    inc rsi
    dec r14d
    jmp .ns_skip

.ns_call:
    mov r13, rsi               ; save remaining text ptr (preserved across calls)
    mov dil, 'C'
    call debug_putc
    mov rsi, r13               ; restore

    ; Debug: print envelope ptr before handler call
    mov dil, 'e'
    call debug_putc
    mov rax, [rsp + 64]
    test rax, rax
    jnz .env_ok
    mov dil, 'z'
    call debug_putc
    jmp .not_cmd
.env_ok:
    mov dil, 'g'
    call debug_putc

    ; Push pointer to handler_args struct (user_len, envelope_id, envelope_id_len)
    lea rax, [rsp + 56]
    push rax

    mov dil, 'h'
    call debug_putc
    mov rax, [r12 + cmd_entry.handler]
    test rax, rax
    jnz .handler_ok
    mov dil, 'n'
    call debug_putc
    add rsp, 8
    jmp .not_cmd
.handler_ok:
    mov dil, 'i'
    call debug_putc

    ; Set handler register args (after debug output to avoid clobber)
    mov rsi, r13                 ; restore remaining text ptr
    lea rdi, [rel namespace_prefix]
    mov edx, r14d
    mov rcx, [rsp + 48]          ; channel_id_len (shifted by push)
    mov r8,  [rsp + 56]          ; user_id_ptr (shifted by push)
    mov r9,  [rsp + 72]          ; envelope_id_ptr (shifted by push)
    mov rax, [r12 + cmd_entry.handler]
    call rax

    mov dil, 'R'
    call debug_putc

    add rsp, 8
    xor eax, eax
    jmp .done

    ; ---- Direct dispatch (command is itself, e.g. /ping) ----
.direct_mode:
    xor ebx, ebx
    mov r14d, [rel cmd_count]
    test r14d, r14d
    jz .not_cmd

.dir_loop:
    cmp ebx, r14d
    jae .not_cmd

    mov eax, ebx
    mov ecx, cmd_entry_size
    mul ecx
    lea r15, [rel cmd_table + rax]

    cmp dword [r15 + cmd_entry.flags], CMD_DIRECT
    jne .dir_next

    mov eax, [r15 + cmd_entry.name_len]
    cmp eax, [rsp + 8]
    jne .dir_next

    mov rdi, [r15 + cmd_entry.name_ptr]
    mov rsi, [rsp]
    mov ecx, [rsp + 8]
    cld
    repe cmpsb
    je .dir_found

.dir_next:
    inc ebx
    jmp .dir_loop

.dir_found:
    lea rax, [rsp + 56]
    push rax

    mov rdi, [rsp + 8]
    mov rsi, [rsp + 24]
    mov rdx, [rsp + 32]
    mov rcx, [rsp + 40]
    mov r8,  [rsp + 48]
    mov r9,  [rsp + 56]

    mov rax, [r15 + cmd_entry.handler]
    call rax

    add rsp, 8
    xor eax, eax
    jmp .done

.parse_err:
    mov dil, 'E'
    call debug_putc
    jmp .not_cmd
.not_cmd:
    mov dil, 'X'
    call debug_putc
    mov eax, 1

.done:
    add rsp, 80
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; void slack_send_response(const char *envelope_id, uint32_t envelope_id_len,
;                          const char *text, uint32_t text_len)
; rdi = envelope_id ptr, esi = envelope_id len
; rdx = text ptr, ecx = text len
slack_send_response:
    cld
    push r12
    push r13
    push r14
    push r15
    sub rsp, 1024

    ; Save args before debug_putc clobbers them
    mov r12, rdi
    mov r13d, esi
    mov r14, rdx
    mov r15d, ecx

    mov dil, 'S'
    call debug_putc

    ; Build JSON: {"envelope_id":"<id>","payload":{"text":"<text>"}}
    lea rdi, [rsp]

    lea rsi, [rel resp_prefix]
    mov ecx, resp_prefix_len
    rep movsb

    mov rsi, r12
    mov ecx, r13d
    rep movsb

    lea rsi, [rel resp_middle]
    mov ecx, resp_middle_len
    rep movsb

    mov rsi, r14
    mov ecx, r15d
    rep movsb

    lea rsi, [rel resp_suffix]
    mov ecx, resp_suffix_len
    rep movsb

    ; Total length = rdi - rsp
    mov rax, rdi
    sub rax, rsp
    mov ebx, eax

    ; Debug: hex dump the response JSON
    mov dil, 'J'
    call debug_putc
    lea rdi, [rsp]
    mov esi, ebx
    call debug_hexdump

    ; Send as WS_TEXT frame
    mov rax, [rel ws_ctx_ptr]
    test rax, rax
    jz .skip_send

    mov rdi, rax
    mov esi, [rel ws_fd]
    mov edx, WS_TEXT
    lea rcx, [rsp]
    mov r8d, ebx
    call ws_send_frame

.skip_send:
    add rsp, 1024
    pop r15
    pop r14
    pop r13
    pop r12
    ret
