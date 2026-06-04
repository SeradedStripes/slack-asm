; small test harness for util/socket helpers
BITS 64
default rel

extern make_sockaddr_in
extern sys_socket
extern save_errno_and_ret
extern sys_close

section .rodata
ok_msg:    db "socket ok", 10
ok_len:    equ $ - ok_msg
err_msg:   db "socket failed", 10
err_len:   equ $ - err_msg

section .text
global test_harness

test_harness:
    ; allocate 32 bytes for sockaddr
    sub rsp, 32

    lea rdi, [rsp]          ; dst ptr
    mov esi, 80             ; port (host order)
    mov edx, 0x5DB8D822     ; IP 93.184.216.34 (example.com)
    call make_sockaddr_in

    ; create socket for sys_socket(AF_INET=2, SOCK_STREAM=1, proto=0)
    mov rdi, 2
    mov rsi, 1
    xor rdx, rdx
    call sys_socket

    ; save errno if error, returns -1 on error
    call save_errno_and_ret
    cmp eax, -1
    je .failed

    ; if success print ok_msg
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel ok_msg]
    mov rdx, ok_len
    syscall

    ; close the socket
    mov edi, eax
    call sys_close

    add rsp, 32
    ret

.failed:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel err_msg]
    mov rdx, err_len
    syscall

    add rsp, 32
    ret
