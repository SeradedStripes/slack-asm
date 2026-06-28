; Debug and error reporting utilities.

BITS 64
default rel

%define SYS_write  1
%define SYS_exit   60
%define STDERR     2

; Exported functions
global debug_putc
global debug_puts
global debug_hexdump
global error_exit

section .rodata
hex_chars: db "0123456789abcdef"
err_prefix: db "ERROR: "
err_prefix_len: equ $ - err_prefix

section .bss
debug_char: resb 1
debug_hex_out: resb 2048

section .text

; Write one byte to stderr.
;  dil = byte to write.
debug_putc:
    mov [debug_char], dil
    mov eax, SYS_write
    mov edi, STDERR
    lea rsi, [debug_char]
    mov edx, 1
    syscall
    ret

; Write raw bytes to stderr.
;  rdi = buffer, rsi = length.
debug_puts:
    mov eax, SYS_write
    mov edx, esi
    mov esi, edi
    mov edi, STDERR
    syscall
    ret

; Write hex dump of buffer to stderr + newline.
;  rdi = buffer, rsi = length.
; Caps output at 1024 bytes (2048 hex chars).
debug_hexdump:
    push rbx
    push r12
    push r13
    mov r12, rsi
    mov r13, rdi
    cmp r12, 1024
    jbe .hex_loop
    mov r12, 1024
.hex_loop:
    xor ebx, ebx
    test r12d, r12d
    jz .hex_flush
.hl_next:
    movzx eax, byte [r13 + rbx]
    mov ecx, eax
    shr ecx, 4
    mov cl, [hex_chars + rcx]
    mov [debug_hex_out + rbx*2], cl
    and eax, 0x0f
    mov al, [hex_chars + rax]
    mov [debug_hex_out + rbx*2 + 1], al
    inc ebx
    cmp ebx, r12d
    jb .hl_next
.hex_flush:
    lea rsi, [debug_hex_out]
    lea edx, [r12 + r12]
    mov eax, SYS_write
    mov edi, STDERR
    syscall
    mov byte [debug_char], 10
    mov eax, SYS_write
    mov edi, STDERR
    lea rsi, [debug_char]
    mov edx, 1
    syscall
    pop r13
    pop r12
    pop rbx
    ret

; Print "ERROR: " to stderr and exit with code edi.
error_exit:
    push rdi
    mov eax, SYS_write
    mov edi, STDERR
    lea rsi, [err_prefix]
    mov edx, err_prefix_len
    syscall
    pop rdi
    mov eax, SYS_exit
    syscall
