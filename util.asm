; address construction and simple error handling helpers
BITS 64
default rel

%define AF_INET 2

section .bss
last_errno:    resd 1

section .text
global make_sockaddr_in
global save_errno_and_ret
global get_last_errno

; make_sockaddr_in(void *dst, uint16_t port_hostorder, uint32_t ip_hostorder)
; Writes a struct sockaddr_in of 16 bytes to dst and returns 16 in eax
make_sockaddr_in:
    ; rdi = dst, rsi = port, rdx = ip
    mov word [rdi], AF_INET

    ; swap bytes of ax
    mov ax, si
    rol ax, 8
    mov word [rdi + 2], ax

    ; byte-swap eax
    mov eax, edx
    bswap eax
    mov dword [rdi + 4], eax

    ; zero sin_zero
    mov qword [rdi + 8], 0

    mov eax, 16
    ret

; save_errno_and_ret
; Expects syscall return value in rax
; If rax < 0 then stores -rax into last_errno and returns -1 in eax
; Otherwise returns the original rax
save_errno_and_ret:
    cmp rax, 0
    jge .ok
    neg rax
    mov [rel last_errno], eax
    mov eax, -1
    ret
.ok:
    ret

get_last_errno:
    mov eax, [rel last_errno]
    ret
