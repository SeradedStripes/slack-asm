; Provides small, direct wrappers around the kernel socket APIs.

BITS 64
default rel

%define SYS_socket   41
%define SYS_connect  42
%define SYS_sendto   44
%define SYS_recvfrom 45
%define SYS_close     3

section .text

global sys_socket
global sys_connect
global sys_socketpair
global sys_send
global sys_recv
global sys_close

; int sys_socket(int domain, int type, int protocol)
sys_socket:
    mov rax, SYS_socket
    syscall
    ret

; int sys_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
sys_connect:
    mov rax, SYS_connect
    syscall
    ret

; ssize_t sys_send(int fd, const void *buf, size_t len, int flags)
sys_send:
    mov rax, SYS_sendto
    ; syscall expects 4th arg in r10 (not rcx)
    mov r10, rcx
    xor r8, r8
    xor r9, r9
    syscall
    ret

; ssize_t sys_recv(int fd, void *buf, size_t len, int flags)
sys_recv:
    mov rax, SYS_recvfrom
    mov r10, rcx
    xor r8, r8
    xor r9, r9
    syscall
    ret

; int sys_socketpair(int domain, int type, int protocol, int sv[2])
; rdi=domain, rsi=type, rdx=protocol, rcx=sv
sys_socketpair:
    mov rax, 53  ; SYS_socketpair
    mov r10, rcx ; sv array pointer in r10 (per syscall convention)
    syscall
    ret

; int sys_close(int fd)
sys_close:
    mov rax, SYS_close
    syscall
    ret
