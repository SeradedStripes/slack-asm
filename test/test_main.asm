BITS 64
default rel

global _start

extern test_register, test_exit
extern run_sha256_hmac_tests
extern run_prf_kdf_tests
extern run_tls_record_tests
extern run_tls_handshake_tests
extern run_tls_connect_tests
extern run_aes_cbc_tests
extern run_encrypted_record_tests
extern run_x509_tests
extern run_http_tests
extern run_rsa_tests
extern run_gcm_tests

section .rodata
name_sha256_hmac:      db "sha256+hmac", 0
name_prf_kdf:          db "prf+kdf", 0
name_tls_record:       db "tls_record", 0
name_tls_handshake:    db "tls_handshake", 0
name_tls_connect:      db "tls_connect", 0
name_aes_cbc:          db "aes_cbc", 0
name_enc_record:       db "encrypted_record", 0
name_x509:             db "x509", 0
name_http:             db "http", 0
name_rsa:              db "rsa", 0
name_gcm:              db "gcm", 0

section .text
_start:
    lea rdi, [rel name_sha256_hmac]
    lea rsi, [rel run_sha256_hmac_tests]
    call test_register

    lea rdi, [rel name_prf_kdf]
    lea rsi, [rel run_prf_kdf_tests]
    call test_register

    lea rdi, [rel name_tls_record]
    lea rsi, [rel run_tls_record_tests]
    call test_register

    lea rdi, [rel name_tls_handshake]
    lea rsi, [rel run_tls_handshake_tests]
    call test_register

    lea rdi, [rel name_tls_connect]
    lea rsi, [rel run_tls_connect_tests]
    call test_register

    lea rdi, [rel name_aes_cbc]
    lea rsi, [rel run_aes_cbc_tests]
    call test_register

    lea rdi, [rel name_enc_record]
    lea rsi, [rel run_encrypted_record_tests]
    call test_register

    lea rdi, [rel name_x509]
    lea rsi, [rel run_x509_tests]
    call test_register

    lea rdi, [rel name_http]
    lea rsi, [rel run_http_tests]
    call test_register

    lea rdi, [rel name_rsa]
    lea rsi, [rel run_rsa_tests]
    call test_register

    lea rdi, [rel name_gcm]
    lea rsi, [rel run_gcm_tests]
    call test_register

    call test_exit
