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
    .thread_ts     resq 1
    .thread_ts_len resq 1
endstruc

; Channel->ts cache: fixed-size entries, zero-padded
MAX_CACHE_ENTRIES  equ 16
CACHE_CHAN_SZ      equ 24
CACHE_TS_SZ        equ 24

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
key_thread_ts:      db '"thread_ts"'
key_thread_ts_len:  equ $ - key_thread_ts
key_ts:             db '"ts"'
key_ts_len:         equ $ - key_ts

event_callback_str: db "event_callback"
event_callback_len: equ $ - event_callback_str
key_events_channel: db '"channel"'
key_events_channel_len: equ $ - key_events_channel

resp_prefix:          db '{"envelope_id":"'
resp_prefix_len:      equ $ - resp_prefix
resp_mid_ephemeral:   db '","payload":{"text":"'
resp_mid_ephemeral_len: equ $ - resp_mid_ephemeral
resp_mid_channel:     db '","payload":{"response_type":"in_channel","text":"'
resp_mid_channel_len: equ $ - resp_mid_channel
resp_mid_thread:      db '","payload":{"response_type":"in_channel","thread_ts":"'
resp_mid_thread_len:  equ $ - resp_mid_thread
resp_mid_thread_text: db '","text":"'
resp_mid_thread_text_len: equ $ - resp_mid_thread_text
resp_suffix:          db '"}}'
resp_suffix_len:      equ $ - resp_suffix

section .bss
cmd_table:       resb cmd_entry_size * MAX_CMDS
cmd_count:       resd 1

chan_cache_chan: resb MAX_CACHE_ENTRIES * CACHE_CHAN_SZ
chan_cache_ts:   resb MAX_CACHE_ENTRIES * CACHE_TS_SZ
chan_cache_used: resd 1

section .text
global cmd_init, cmd_register, cmd_dispatch, slack_send_response, slack_send_response_ephemeral, slack_send_response_thread

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
    lea rbx, [cmd_table + rax]

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
    sub rsp, 128

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

    ; Check if it's an events_api event (type: "event_callback")
    cmp edx, event_callback_len
    je .check_event_callback

    ; Check if it's a slash_commands event
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
    jmp .handle_slash

.check_event_callback:
    push rsi
    push rdi
    mov rsi, rax
    lea rdi, [rel event_callback_str]
    mov ecx, event_callback_len
    cld
    repe cmpsb
    pop rdi
    pop rsi
    jne .not_cmd

    ; ---- events_api message event: cache channel+ts for thread replies ----
    ; Extract "channel" from event
    mov rdi, r12
    mov esi, r13d
    lea rdx, [rel key_events_channel]
    mov ecx, key_events_channel_len
    call json_get_str
    test rax, rax
    jz .not_cmd
    mov [rsp + 96], rax
    mov [rsp + 104], edx

    ; Extract "ts" from event
    mov rdi, r12
    mov esi, r13d
    lea rdx, [rel key_ts]
    mov ecx, key_ts_len
    call json_get_str
    test rax, rax
    jz .not_cmd
    mov [rsp + 112], rax
    mov [rsp + 120], edx

    ; Look for existing cache entry for this channel
    xor r14d, r14d
    mov r15d, [rel chan_cache_used]
    test r15d, r15d
    jz .cache_add_new

.cache_find_loop:
    cmp r14d, r15d
    jae .cache_add_new

    mov eax, r14d
    mov ecx, CACHE_CHAN_SZ
    mul ecx
    lea rbx, [rel chan_cache_chan]
    add rbx, rax

    ; Compare channel (exact match of channel_len bytes)
    mov rdi, [rsp + 96]
    mov rsi, rbx
    mov ecx, [rsp + 104]
    cmp ecx, CACHE_CHAN_SZ
    ja .cache_next
    cld
    repe cmpsb
    jne .cache_next

    ; Check that cached string ends at channel_len
    mov eax, [rsp + 104]
    cmp byte [rbx + rax], 0
    jne .cache_next

    ; Found – update ts in this entry (zero then copy)
    mov eax, r14d
    mov ecx, CACHE_TS_SZ
    mul ecx
    lea rdi, [rel chan_cache_ts]
    add rdi, rax
    mov ebp, eax
    xor eax, eax
    mov ecx, CACHE_TS_SZ
    rep stosb
    lea rdi, [rel chan_cache_ts]
    add rdi, rbp
    mov rsi, [rsp + 112]
    mov ecx, [rsp + 120]
    cmp ecx, CACHE_TS_SZ
    jbe .cache_copy_upd
    mov ecx, CACHE_TS_SZ
.cache_copy_upd:
    cld
    rep movsb
    xor eax, eax
    jmp .done_events

.cache_next:
    inc r14d
    jmp .cache_find_loop

.cache_add_new:
    cmp r15d, MAX_CACHE_ENTRIES
    jae .done_events

    ; Copy channel into new entry (BSS is already zeroed)
    mov eax, r15d
    mov ecx, CACHE_CHAN_SZ
    mul ecx
    lea rdi, [rel chan_cache_chan]
    add rdi, rax
    mov rsi, [rsp + 96]
    mov ecx, [rsp + 104]
    cmp ecx, CACHE_CHAN_SZ
    jbe .cache_copy_chan
    mov ecx, CACHE_CHAN_SZ
.cache_copy_chan:
    cld
    rep movsb

    ; Copy ts into new entry
    mov eax, r15d
    mov ecx, CACHE_TS_SZ
    mul ecx
    lea rdi, [rel chan_cache_ts]
    add rdi, rax
    mov rsi, [rsp + 112]
    mov ecx, [rsp + 120]
    cmp ecx, CACHE_TS_SZ
    jbe .cache_copy_ts
    mov ecx, CACHE_TS_SZ
.cache_copy_ts:
    cld
    rep movsb

    inc dword [rel chan_cache_used]

.done_events:
    xor eax, eax
    jmp .done

.handle_slash:
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

    ; Look up cached ts for this channel (for thread replies)
    xor eax, eax
    mov [rsp + 80], rax          ; thread_ts ptr (default NULL)
    mov [rsp + 88], eax          ; thread_ts len (default 0)
    mov r14d, [rel chan_cache_used]
    test r14d, r14d
    jz .extract_user

    xor r15d, r15d
.ts_lookup_loop:
    cmp r15d, r14d
    jae .extract_user

    mov eax, r15d
    mov ecx, CACHE_CHAN_SZ
    mul ecx
    lea rbx, [rel chan_cache_chan]
    add rbx, rax

    mov rdi, [rsp + 32]
    mov esi, [rsp + 40]
    cmp esi, CACHE_CHAN_SZ
    ja .ts_lookup_next
    mov rdi, [rsp + 32]
    mov rsi, rbx
    mov ecx, [rsp + 40]
    cld
    repe cmpsb
    jne .ts_lookup_next

    mov edi, [rsp + 40]
    cmp byte [rbx + rdi], 0
    jne .ts_lookup_next

    ; Found cache entry, set thread_ts
    mov eax, r15d
    mov ecx, CACHE_TS_SZ
    mul ecx
    lea rbx, [rel chan_cache_ts]
    add rbx, rax
    mov [rsp + 80], rbx

    xor edx, edx
.ts_scan_len:
    cmp edx, CACHE_TS_SZ
    jae .ts_len_done
    cmp byte [rbx + rdx], 0
    je .ts_len_done
    inc edx
    jmp .ts_scan_len
.ts_len_done:
    mov [rsp + 88], edx
    jmp .extract_user

.ts_lookup_next:
    inc r15d
    jmp .ts_lookup_loop

.extract_user:
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

    ; thread_ts set from cache above (or NULL if no cached message ts)
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
    lea r12, [cmd_table + rax]

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
    lea r15, [cmd_table + rax]

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
    add rsp, 128
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
; Sends response visible to everyone in the channel (in_channel)
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

    mov dil, 'C'
    call debug_putc

    ; Build JSON: {"envelope_id":"<id>","payload":{"response_type":"in_channel","text":"<text>"}}
    lea rdi, [rsp]

    lea rsi, [rel resp_prefix]
    mov ecx, resp_prefix_len
    rep movsb

    mov rsi, r12
    mov ecx, r13d
    rep movsb

    lea rsi, [rel resp_mid_channel]
    mov ecx, resp_mid_channel_len
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

; void slack_send_response_ephemeral(const char *envelope_id, uint32_t envelope_id_len,
;                                    const char *text, uint32_t text_len)
; Same as slack_send_response but response is only visible to the invoking user
slack_send_response_ephemeral:
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

    lea rsi, [rel resp_mid_ephemeral]
    mov ecx, resp_mid_ephemeral_len
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
    jz .ep_skip

    mov rdi, rax
    mov esi, [rel ws_fd]
    mov edx, WS_TEXT
    lea rcx, [rsp]
    mov r8d, ebx
    call ws_send_frame

.ep_skip:
    add rsp, 1024
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; void slack_send_response_thread(const char *envelope_id, uint32_t envelope_id_len,
;                                  const char *text, uint32_t text_len,
;                                  const char *thread_ts, uint32_t thread_ts_len)
; rdi = envelope_id ptr, esi = envelope_id_len
; rdx = text ptr, ecx = text_len
; r8 = thread_ts ptr, r9d = thread_ts_len
; Sends response in a thread
slack_send_response_thread:
    cld
    push r12
    push r13
    push r14
    push r15
    sub rsp, 1024

    ; Save args
    mov r12, rdi
    mov r13d, esi
    mov r14, rdx
    mov r15d, ecx
    push r8
    push r9

    mov dil, 'T'
    call debug_putc

    ; Build JSON: {"envelope_id":"<id>","payload":{"thread_ts":"<ts>","text":"<text>"}}
    lea rdi, [rsp]

    lea rsi, [rel resp_prefix]
    mov ecx, resp_prefix_len
    rep movsb

    mov rsi, r12
    mov ecx, r13d
    rep movsb

    lea rsi, [rel resp_mid_thread]
    mov ecx, resp_mid_thread_len
    rep movsb

    pop r9
    pop r8
    mov rsi, r8
    mov ecx, r9d
    rep movsb

    lea rsi, [rel resp_mid_thread_text]
    mov ecx, resp_mid_thread_text_len
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
    jz .thr_skip

    mov rdi, rax
    mov esi, [rel ws_fd]
    mov edx, WS_TEXT
    lea rcx, [rsp]
    mov r8d, ebx
    call ws_send_frame

.thr_skip:
    add rsp, 1024
    pop r15
    pop r14
    pop r13
    pop r12
    ret
