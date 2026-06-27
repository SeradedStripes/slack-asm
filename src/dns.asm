; Minimal DNS resolver for slack-asm
; Resolves hostnames to IPv4 addresses via Google DNS (8.8.8.8)
; Yes there are better DNS servers but it was late at night at so i picked the first one I thought of.
; Change DNS_SERVER Constant to use a different server.

BITS 64
default rel

%define AF_INET     2
%define SOCK_DGRAM  2
%define SYS_socket  41
%define SYS_sendto  44
%define SYS_recvfrom 45
%define SYS_close   3

%define DNS_SERVER  0x08080808
%define DNS_PORT    53

section .bss
dns_buf:       resb 512
dns_sockaddr:  resb 16

section .text
global dns_resolve

extern make_sockaddr_in
extern sys_socket
extern sys_close

; uint32_t dns_resolve(const char *hostname, uint64_t hostlen)
; Resolves hostname to IPv4 address in host byte order.
; Returns 0 on error.
; rdi = hostname, rsi = hostlen
dns_resolve:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                  ; hostname
    mov r13, rsi                  ; hostlen
    lea r14, [dns_buf]            ; buffer for query/response

    test r13, r13
    jz .error
    cmp r13, 255                  ; DNS max label sequence
    ja .error

    ; Build DNS Query
    ; Header (12 bytes)
    mov word [r14], 0x3412        ; ID = 0x1234 in net order
    mov word [r14 + 2], 0x0001    ; flags: RD=1, net order 0x0100
    mov word [r14 + 4], 0x0100    ; QDCOUNT = 1, net order 0x0001
    mov word [r14 + 6], 0x0000    ; ANCOUNT = 0
    mov word [r14 + 8], 0x0000    ; NSCOUNT = 0
    mov word [r14 + 10], 0x0000   ; ARCOUNT = 0

    ; Encode QNAME: "slack.com" -> \x05slack\x03com\x00
    lea rdi, [r14 + 12]
    mov rsi, r12
    mov rcx, r13
    xor r8d, r8d
    xor r9b, r9b
    mov r8, rdi
    inc rdi

.enc_loop:
    cmp rcx, 0
    je .enc_done
    mov al, [rsi]
    inc rsi
    dec rcx
    cmp al, '.'
    je .enc_dot
    mov [rdi], al
    inc rdi
    inc r9b
    jmp .enc_loop

.enc_dot:
    mov [r8], r9b
    xor r9b, r9b
    mov r8, rdi
    inc rdi
    jmp .enc_loop

.enc_done:
    mov [r8], r9b
    mov byte [rdi], 0x00
    inc rdi

    ; QTYPE (2) + QCLASS (2), net order 0x0001 for both
    mov word [rdi], 0x0100        ; QTYPE = A record
    mov word [rdi + 2], 0x0100    ; QCLASS = IN class
    add rdi, 4

    sub rdi, r14
    mov r15, rdi                  ; query length

    ; Create UDP socket
    mov edi, AF_INET
    mov esi, SOCK_DGRAM
    xor edx, edx
    call sys_socket
    test eax, eax
    js .error
    mov ebx, eax                  ; fd

    ; Build sockaddr_in for DNS server
    lea rdi, [dns_sockaddr]
    mov esi, DNS_PORT
    mov edx, DNS_SERVER
    call make_sockaddr_in

    ; Send DNS query
    mov edi, ebx
    lea rsi, [dns_buf]
    mov rdx, r15
    xor r10d, r10d
    lea r8, [dns_sockaddr]
    mov r9d, 16
    mov rax, SYS_sendto
    syscall
    test rax, rax
    js .close_sock

    ; Receive DNS response
    mov edi, ebx
    lea rsi, [dns_buf]
    mov edx, 512
    xor r10d, r10d
    xor r8, r8
    xor r9, r9
    mov rax, SYS_recvfrom
    syscall
    test rax, rax
    js .close_sock
    cmp rax, 12
    jb .close_sock
    mov r15, rax                  ; response length

    ; Validate header
    mov ax, [dns_buf]
    cmp ax, 0x3412                ; stored as little-endian, ID=0x1234 net
    jne .close_sock

    mov ax, [dns_buf + 2]
    xchg ah, al
    test ax, 0x8000               ; QR bit
    jz .close_sock
    and ax, 0x000F                ; RCODE
    jnz .close_sock

    mov ax, [dns_buf + 6]
    xchg ah, al
    test ax, ax
    jz .close_sock
    mov r12d, eax                 ; answer count

    ; Skip question section
    lea rdi, [dns_buf + 12]
    mov rcx, r15
    sub rcx, 12
    jbe .close_sock

.skip_qname:
    mov al, [rdi]
    test al, 0xC0
    jnz .qname_ptr
    cmp al, 0
    je .qname_term
    inc rdi
    dec rcx
    jz .close_sock
    movzx rax, al
    add rdi, rax
    sub rcx, rax
    ja .skip_qname
    jmp .close_sock

.qname_term:
    inc rdi                       ; skip the 0x00 terminator
    dec rcx
    jmp .qname_end

.qname_ptr:
    add rdi, 2                    ; skip compression pointer
    sub rcx, 2
    jbe .close_sock

.qname_end:
    add rdi, 4                    ; skip QTYPE and QCLASS
    sub rcx, 4
    jbe .close_sock

    ; Parse answers
    mov r14d, r12d

.next_answer:
    test r14d, r14d
    jz .close_sock
    dec r14d

    cmp rcx, 12
    jb .close_sock

    ; Skip NAME field (usually a 2-byte pointer, but handle both forms)
.ans_name:
    cmp rcx, 0
    jbe .close_sock
    mov al, [rdi]
    test al, 0xC0
    jnz .ans_ptr
    cmp al, 0
    je .ans_name_end
    inc rdi
    dec rcx
    jz .close_sock
    movzx rax, al
    add rdi, rax
    sub rcx, rax
    jmp .ans_name

.ans_ptr:
    add rdi, 2
    sub rcx, 2
    jb .close_sock
    jmp .parse_rr

.ans_name_end:
    inc rdi
    dec rcx
    ; fall through

.parse_rr:
    ; rdi points to TYPE (2), CLASS (2), TTL (4), RDLENGTH (2), RDATA
    cmp rcx, 10
    jb .close_sock

    mov ax, [rdi]
    xchg ah, al
    ; Lowkey should of named them B records lmao
    cmp ax, 1                     ; A record?
    jne .skip_this

    mov ax, [rdi + 2]
    xchg ah, al
    cmp ax, 1                     ; IN class?
    jne .skip_this

    mov ax, [rdi + 8]
    xchg ah, al
    cmp ax, 4                     ; RDLENGTH = 4?
    jne .skip_this

    mov r15d, [rdi + 10]
    bswap r15d                    ; convert to host byte order

    mov edi, ebx
    call sys_close
    mov eax, r15d
    jmp .done

.skip_this:
    mov ax, [rdi + 8]
    xchg ah, al
    movzx eax, ax
    add eax, 10
    add rdi, rax
    sub rcx, rax
    ja .next_answer

.close_sock:
    mov edi, ebx
    call sys_close

.error:
    xor eax, eax

.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
