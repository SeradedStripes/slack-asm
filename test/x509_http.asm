BITS 64
default rel

global run_x509_tests
global run_http_tests

extern x509_parse_cert, x509_check_validity
extern cert_not_before, cert_not_after
extern server_pubkey_n_len, server_pubkey_e_len
extern http_start_request, http_add_header, http_finish_headers
extern http_parse_response
extern http_body_ptr, http_body_len, http_status

section .rodata
http_get_method:    db "GET"
http_get_method_len: equ $ - http_get_method
http_post_method:   db "POST"
http_post_method_len: equ $ - http_post_method

http_test_get_path: db "/api/test"
http_test_get_path_len: equ $ - http_test_get_path
http_test_post_path: db "/api/chat.postMessage"
http_test_post_path_len: equ $ - http_test_post_path
http_test_host_name: db "Host"
http_test_host_name_len: equ $ - http_test_host_name
http_test_ct_name:  db "Content-Type"
http_test_ct_name_len: equ $ - http_test_ct_name
http_test_host_val: db "slack.com"
http_test_host_val_len: equ $ - http_test_host_val
http_test_ct_val:   db "application/json"
http_test_ct_val_len: equ $ - http_test_ct_val

http_get_req_len:     equ 43
http_post_req_len:    equ 139

http_test_response:
db "HTTP/1.1 200 OK", 0x0D, 0x0A
db "Content-Type: application/json", 0x0D, 0x0A
db "Content-Length: 12", 0x0D, 0x0A
db 0x0D, 0x0A
db '{"status":"ok"}'
http_test_response_len: equ $ - http_test_response

http_post_body: db '{"channel":"C123","text":"Hi"}'
http_post_body_len: equ $ - http_post_body

extern cert_template_len_val
extern cert_buf

section .bss
recv_buf: resb 1024

section .text
run_x509_tests:
    push rbx

    lea rdi, [rel cert_buf]
    mov esi, [rel cert_template_len_val]
    call x509_parse_cert
    test eax, eax
    jnz .fail

    cmp dword [rel cert_not_before], 0
    je .fail
    cmp dword [rel cert_not_after], 0
    je .fail
    mov eax, [rel cert_not_before]
    cmp eax, [rel cert_not_after]
    jae .fail

    cmp word [rel server_pubkey_n_len], 0
    je .fail
    cmp word [rel server_pubkey_e_len], 0
    je .fail

    call x509_check_validity
    test eax, eax
    jnz .fail

    xor eax, eax
    pop rbx
    ret

.fail:
    mov eax, 1
    pop rbx
    ret

run_http_tests:
    push rbx
    push r12

    lea rdi, [rel recv_buf]
    lea rsi, [rel http_get_method]
    mov edx, http_get_method_len
    lea rcx, [rel http_test_get_path]
    mov r8d, http_test_get_path_len
    call http_start_request
    mov r12d, eax

    cmp word [rel recv_buf], 'GE'
    jne .http_fail
    cmp byte [rel recv_buf + 2], 'T'
    jne .http_fail

    lea rdi, [recv_buf + r12]
    lea rsi, [rel http_test_host_name]
    mov edx, http_test_host_name_len
    lea rcx, [rel http_test_host_val]
    mov r8d, http_test_host_val_len
    call http_add_header
    add r12d, eax

    lea rdi, [recv_buf + r12]
    call http_finish_headers
    add r12d, eax

    cmp r12d, http_get_req_len
    jne .http_fail

    ; HTTP response parser test
    lea rdi, [rel http_test_response]
    mov esi, http_test_response_len
    call http_parse_response
    cmp eax, 200
    jne .http_fail

    cmp dword [rel http_status], 200
    jne .http_fail

    mov rax, [rel http_body_len]
    cmp rax, 12
    jne .http_fail

    mov rsi, [rel http_body_ptr]
    cmp byte [rsi], '{'
    jne .http_fail

    pop r12
    pop rbx
    xor eax, eax
    ret

.http_fail:
    pop r12
    pop rbx
    mov eax, 1
    ret
