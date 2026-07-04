BITS 64
default rel

%define SYS_write  1
%define SYS_exit   60
%define STDERR     2
%define STDOUT     1

struc test_desc
    .name   resq 1
    .func   resq 1
endstruc

section .data
test_count:     dd 0
test_passed:    dd 0
test_failed:    dd 0

section .rodata
str_pass:   db "[PASS] "
str_pass_len: equ $ - str_pass
str_fail:   db "[FAIL] "
str_fail_len: equ $ - str_fail
str_summary: db "-----------------", 10
str_summary_len: equ $ - str_summary
str_all_pass: db "All tests passed.", 10
str_all_pass_len: equ $ - str_all_pass
str_some_fail: db " tests passed, "
str_some_fail_len: equ $ - str_some_fail
str_out_of:  db " out of "
str_out_of_len: equ $ - str_out_of
str_failed_out: db " failed.", 10
str_failed_out_len: equ $ - str_failed_out
str_newline: db 10
str_newline_len: equ $ - str_newline
str_spaces:  db "                "
str_spaces_len: equ $ - str_spaces

section .text

; Print raw string to stdout
; rdi = ptr, esi = len
_print_str:
    mov eax, SYS_write
    mov edx, esi
    mov rsi, rdi
    mov edi, STDOUT
    syscall
    ret

; Print [PASS] name
; rdi = name ptr
_print_pass:
    push rdi
    lea rdi, [rel str_pass]
    mov esi, str_pass_len
    call _print_str
    pop rdi
    mov esi, 1
    ; Find string length (until null byte)
    push rdi
    xor eax, eax
    mov ecx, -1
    repne scasb
    not ecx
    dec ecx
    mov esi, ecx
    pop rdi
    call _print_str
    lea rdi, [rel str_newline]
    mov esi, str_newline_len
    call _print_str
    ret

; Print [FAIL] name
; rdi = name ptr
_print_fail:
    push rdi
    lea rdi, [rel str_fail]
    mov esi, str_fail_len
    call _print_str
    pop rdi
    push rdi
    xor eax, eax
    mov ecx, -1
    repne scasb
    not ecx
    dec ecx
    mov esi, ecx
    pop rdi
    call _print_str
    lea rdi, [rel str_newline]
    mov esi, str_newline_len
    call _print_str
    ret

; Print a 32-bit unsigned integer to stdout
; edi = value
_print_uint32:
    push rbx
    sub rsp, 16
    mov rbx, rsp
    add rbx, 15
    mov byte [rbx], 0
    mov eax, edi
    mov ecx, 10
.loop:
    dec rbx
    xor edx, edx
    div ecx
    add dl, '0'
    mov [rbx], dl
    test eax, eax
    jnz .loop
    mov rdi, rbx
    mov rsi, rsp
    add rsi, 15
    sub rsi, rbx
    call _print_str
    add rsp, 16
    pop rbx
    ret

global test_register
; Register a test
; rdi = name ptr (null-terminated), rsi = function ptr
test_register:
    push rbx
    mov eax, [rel test_count]
    mov ecx, test_desc_size
    mul ecx
    lea rbx, [test_table + rax]
    mov [rbx + test_desc.name], rdi
    mov [rbx + test_desc.func], rsi
    inc dword [rel test_count]
    pop rbx
    ret

global test_run_all
; Run all registered tests, print results
; Returns 0 in eax if all passed, 1 if any failed
test_run_all:
    push rbx
    push r12
    push r13

    xor r12d, r12d
    mov r13d, [rel test_count]
    test r13d, r13d
    jz .summary

.loop:
    cmp r12d, r13d
    jae .summary

    mov eax, r12d
    mov ecx, test_desc_size
    mul ecx
    lea rbx, [test_table + rax]

    mov rax, [rbx + test_desc.func]
    call rax

    test eax, eax
    jnz .fail

    mov rdi, [rbx + test_desc.name]
    call _print_pass
    inc dword [rel test_passed]
    jmp .next

.fail:
    mov rdi, [rbx + test_desc.name]
    call _print_fail
    inc dword [rel test_failed]

.next:
    inc r12d
    jmp .loop

.summary:
    lea rdi, [rel str_summary]
    mov esi, str_summary_len
    call _print_str

    mov edi, [rel test_failed]
    test edi, edi
    jnz .some_failed

    lea rdi, [rel str_all_pass]
    mov esi, str_all_pass_len
    call _print_str
    xor eax, eax
    jmp .done

.some_failed:
    mov edi, [rel test_passed]
    call _print_uint32
    lea rdi, [rel str_some_fail]
    mov esi, str_some_fail_len
    call _print_str
    mov edi, [rel test_failed]
    call _print_uint32
    lea rdi, [rel str_failed_out]
    mov esi, str_failed_out_len
    call _print_str
    lea rdi, [rel str_out_of]
    mov esi, str_out_of_len
    call _print_str
    mov edi, [rel test_count]
    call _print_uint32
    lea rdi, [rel str_failed_out]
    mov esi, str_failed_out_len
    call _print_str
    mov eax, 1

.done:
    pop r13
    pop r12
    pop rbx
    ret

section .bss
test_table:  resb test_desc_size * 128

section .text

global test_exit
; Exit with code based on test results
test_exit:
    call test_run_all
    mov edi, eax
    mov eax, SYS_exit
    syscall
