; Tests for various components of the libraries implemented in the repo.

BITS 64
default rel

extern make_sockaddr_in
extern sys_socket
extern save_errno_and_ret
extern sys_close
extern sha256_init
extern sha256_update
extern sha256_final
extern hmac_sha256
extern tls_init
extern tls_send
extern tls_recv
extern sys_socketpair
extern sys_send
extern sys_recv
extern sys_close
  extern tls_client_start
  extern tls_connect
  extern tls_disconnect
  extern tls_prf
  extern tls_derive_keys
  extern master_secret
  extern client_write_key
  extern server_write_key
  extern client_write_mac_key
  extern server_write_mac_key
  extern client_write_iv
  extern server_write_iv
  extern aes128_cbc_encrypt
  extern aes128_cbc_decrypt
  extern x509_parse_cert
  extern x509_check_validity
  extern cert_not_before
  extern cert_not_after
  extern server_pubkey_n_len
  extern server_pubkey_e_len
  extern pre_master_sec
  extern tls_sha256_ctx
  extern tls_digest
  extern _read_exactly

%define TLS_APPLICATION_DATA 23
%define HS_DONE 3
%define TLS_HANDSHAKE 22
%define TLS_CHANGE_CIPHER_SPEC 20
%define HS_FINISHED 20
%define FINISHED_LEN 12

section .rodata
sock_ok:       db "socket ok", 10
sock_ok_len:   equ $ - sock_ok
sock_fail:     db "socket failed", 10
sock_fail_len: equ $ - sock_fail

expected_empty:
db 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14
db 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24
db 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c
db 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55

expected_abc:
db 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea
db 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23
db 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c
db 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad

test_input:     db "abc"
test_input_len: equ $ - test_input

; HMAC-SHA256 test case - RFC 4231 Test Case 1
hmac_key1:    times 20 db 0x0b
hmac_key1_len: equ $ - hmac_key1
hmac_msg1:    db "Hi There"
hmac_msg1_len: equ $ - hmac_msg1
hmac_expected1:
db 0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53
db 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b
db 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7
db 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7

; HMAC-SHA256 test case - RFC 4231 Test Case 2
hmac_key2:    db "Jefe"
hmac_key2_len: equ $ - hmac_key2
hmac_msg2:    db "what do ya want for nothing?"
hmac_msg2_len: equ $ - hmac_msg2
hmac_expected2:
db 0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e
db 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7
db 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83
db 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43

; HMAC-SHA256 test case - RFC 4231 Test Case 3
hmac_key3:    times 20 db 0xaa
hmac_key3_len: equ $ - hmac_key3
hmac_msg3:    times 50 db 0xdd
hmac_msg3_len: equ $ - hmac_msg3
hmac_expected3:
db 0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46
db 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7
db 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22
db 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe

; HMAC-SHA256 test case - RFC 4231 Test Case 4
hmac_key4:
db 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
db 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
db 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
db 0x19
hmac_key4_len: equ $ - hmac_key4
hmac_msg4:    times 50 db 0xcd
hmac_msg4_len: equ $ - hmac_msg4
hmac_expected4:
db 0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e
db 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a
db 0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07
db 0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b

; HMAC-SHA256 test case - RFC 4231 Test Case 5
hmac_key5:    times 20 db 0x0c
hmac_key5_len: equ $ - hmac_key5
hmac_msg5:    db "Test With Truncation"
hmac_msg5_len: equ $ - hmac_msg5
hmac_expected5:
db 0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0
db 0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55, 0x55, 0x2b
db 0xfa, 0x6f, 0x7c, 0x0a, 0x6a, 0x8a, 0xef, 0x8b
db 0x93, 0xf8, 0x60, 0xaa, 0xb0, 0xcd, 0x20, 0xc5

; HMAC-SHA256 test case - RFC 4231 Test Case 6 (key > 64 bytes, tests hash_key path)
hmac_key6:    times 131 db 0xaa
hmac_key6_len: equ $ - hmac_key6
hmac_msg6:    db "Test Using Larger Than Block-Size Key - Hash Key First"
hmac_msg6_len: equ $ - hmac_msg6
hmac_expected6:
db 0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f
db 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f
db 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14
db 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54

; HMAC-SHA256 test case - RFC 4231 Test Case 7 (key > 64, msg > 64)
hmac_key7:    times 131 db 0xaa
hmac_key7_len: equ $ - hmac_key7
hmac_msg7:    db "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
hmac_msg7_len: equ $ - hmac_msg7
hmac_expected7:
db 0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb
db 0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44
db 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93
db 0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2

; RSA-2048 public key (modulus n and exponent e)
; The modulus is 256 bytes; the leading 0x00 is prepended during DER encoding.
rsa_n:
    db 0xb3, 0x90, 0xcb, 0xa5, 0xf2, 0xca, 0x05, 0xfb
    db 0x39, 0x69, 0x5a, 0x1f, 0x48, 0xb1, 0xfe, 0xff
    db 0x66, 0x23, 0x14, 0xdc, 0xd5, 0x6a, 0xf2, 0x83
    db 0x5e, 0x37, 0x11, 0x86, 0xaa, 0x81, 0xed, 0xea
    db 0x78, 0x0d, 0x51, 0x8b, 0x76, 0x51, 0xc9, 0x4b
    db 0xba, 0x89, 0x8a, 0x9e, 0x94, 0x1a, 0x49, 0xa1
    db 0xae, 0x87, 0x21, 0x54, 0xa2, 0xaa, 0x85, 0xe4
    db 0x6a, 0x47, 0x2c, 0x61, 0xea, 0x62, 0xb1, 0x19
    db 0xa2, 0x3c, 0xe9, 0x46, 0xd3, 0x7b, 0x55, 0x75
    db 0x59, 0x3f, 0x80, 0x53, 0x8d, 0xf9, 0xa5, 0xdd
    db 0x29, 0xdc, 0x3e, 0x9b, 0x48, 0xa4, 0x5b, 0x66
    db 0xe1, 0x38, 0xd7, 0x8c, 0x31, 0x0c, 0x56, 0x53
    db 0x47, 0x6f, 0x25, 0x87, 0xe2, 0x1a, 0x93, 0xd9
    db 0x24, 0xfa, 0x7f, 0x12, 0x15, 0x93, 0x25, 0xc6
    db 0x95, 0x66, 0x88, 0xfb, 0x35, 0x1d, 0x92, 0xc0
    db 0xbd, 0x05, 0x1e, 0x76, 0xe4, 0x54, 0x32, 0xe2
    db 0x93, 0x51, 0x37, 0xc4, 0x26, 0xb0, 0x68, 0x8a
    db 0x9d, 0xdd, 0x22, 0x98, 0xce, 0x07, 0x23, 0xa8
    db 0x3f, 0x73, 0x3e, 0x4d, 0x44, 0xf0, 0xd6, 0x2d
    db 0x91, 0x57, 0x45, 0x27, 0x21, 0x72, 0x2f, 0xc5
    db 0x70, 0x25, 0x0b, 0xd4, 0xa3, 0x88, 0x90, 0x38
    db 0x45, 0x66, 0x5c, 0x0f, 0x75, 0x37, 0xf3, 0x8c
    db 0x92, 0x25, 0x0f, 0xa8, 0x09, 0xf8, 0x64, 0xa4
    db 0x3f, 0x82, 0x5e, 0x96, 0x8e, 0x43, 0xd7, 0x75
    db 0x35, 0x16, 0xf6, 0xd6, 0x6a, 0x0d, 0x78, 0x11
    db 0xda, 0x36, 0xca, 0x38, 0x1c, 0x70, 0x84, 0x8a
    db 0x95, 0x13, 0xba, 0x06, 0xf0, 0xae, 0x9e, 0xb5
    db 0xcf, 0xb0, 0x16, 0x1a, 0x5a, 0x54, 0x81, 0x12
    db 0x22, 0x53, 0xcd, 0x77, 0x71, 0xfe, 0xfd, 0x66
    db 0xb7, 0x72, 0x09, 0xc2, 0xa2, 0x2c, 0x8a, 0xc8
    db 0x50, 0xe2, 0x47, 0x2c, 0xf3, 0x68, 0x81, 0xe2
    db 0xdb, 0xd1, 0x32, 0x3d, 0x0c, 0x94, 0xc8, 0x25
rsa_e:
    db 0x01, 0x00, 0x01             ; 65537

server_random:
    db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    db 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    db 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    db 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f

sh_body:
    db 0x03, 0x03             ; version TLS 1.2
    db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    db 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    db 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    db 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    db 32                     ; session_id length
    times 32 db 0xaa
    db 0x00, 0x3C             ; cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA256
    db 0x00                   ; compression: null
    db 0x00, 0x00             ; extensions length: 0

; Full DER X.509v3 certificate template with placeholder modulus (257 zero bytes).
; Copied into BSS at test startup and modulus patched in.
cert_template:
    db 0x30, 0x82, 0x02, 0xa7, 0x30, 0x82, 0x01, 0x8f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01
    db 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30
    db 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x54, 0x65, 0x73, 0x74
    db 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x31
    db 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33, 0x35, 0x30, 0x31, 0x30
    db 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03
    db 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x54, 0x65, 0x73, 0x74, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43
    db 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01
    db 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01
    db 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7
    db 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
cert_template_end:

cert_template_len equ cert_template_end - cert_template

; ServerHello TLS record offsets (assembler constants derived from cert size)
CERT_OFFSET_IN_RESP equ 81        ; Certificate message starts at byte 81
SHD_OFFSET_IN_RESP equ CERT_OFFSET_IN_RESP + 10 + cert_template_len
RESP_TOTAL_LEN equ SHD_OFFSET_IN_RESP + 4
CERT_HASH_LEN equ 10 + cert_template_len

sf_label:    db "server finished"
sf_label_len: equ $ - sf_label

msg_pass:     db "all tests passed", 10
msg_pass_len: equ $ - msg_pass
msg_fail:     db "test failed", 10
msg_fail_len: equ $ - msg_fail

; PRF test vectors (from Python a reference)
prf_secret:      db "secret"
prf_secret_len:  equ $ - prf_secret
prf_label:       db "test label"
prf_label_len:   equ $ - prf_label
prf_seed:        db "seed1234"
prf_seed_len:    equ $ - prf_seed

prf_expected_32:
db 0x2c, 0x02, 0xf9, 0xaf, 0xb0, 0x8a, 0x8b, 0x4b
db 0x31, 0x25, 0x14, 0x13, 0xf8, 0x3d, 0xea, 0x67
db 0xa2, 0x71, 0x18, 0x0b, 0x42, 0xe7, 0x18, 0xac
db 0xfe, 0x24, 0x5f, 0x9e, 0xa7, 0x39, 0x4c, 0xe9

kdf_master_label: db "master secret"
kdf_master_label_len: equ $ - kdf_master_label
kdf_key_label:    db "key expansion"
kdf_key_label_len: equ $ - kdf_key_label

prf_expected_48:
db 0x2c, 0x02, 0xf9, 0xaf, 0xb0, 0x8a, 0x8b, 0x4b
db 0x31, 0x25, 0x14, 0x13, 0xf8, 0x3d, 0xea, 0x67
db 0xa2, 0x71, 0x18, 0x0b, 0x42, 0xe7, 0x18, 0xac
db 0xfe, 0x24, 0x5f, 0x9e, 0xa7, 0x39, 0x4c, 0xe9
db 0xd2, 0x74, 0x51, 0xb9, 0x2f, 0xb0, 0x7b, 0xaa
db 0x83, 0xcb, 0xf1, 0x7e, 0x10, 0x5c, 0x35, 0xf2

; Key derivation test vectors
kdf_client_random:
db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
db 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
db 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
db 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f

kdf_server_random:
db 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77
db 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
db 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87
db 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f

kdf_pre_master:
db 0x03, 0x03
db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
db 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
db 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
db 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
db 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
db 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
kdf_pre_master_len equ $ - kdf_pre_master

kdf_expected_ms:
db 0x62, 0xf0, 0xf1, 0x70, 0xf4, 0x2e, 0x10, 0xb1
db 0x0e, 0x0a, 0x56, 0xa3, 0xf9, 0x82, 0x8e, 0x3d
db 0x78, 0x97, 0xfa, 0x6e, 0x39, 0xbb, 0x53, 0x13
db 0xc2, 0x2b, 0x91, 0x10, 0x91, 0x36, 0x05, 0xbf
db 0x91, 0xbb, 0x5d, 0xc5, 0xde, 0x98, 0xd9, 0x5d
db 0xc6, 0x5a, 0xd1, 0xc1, 0xff, 0x6f, 0x3d, 0x48

kdf_expected_cwkey:
db 0x70, 0xbf, 0xd2, 0xdd, 0x0c, 0xb4, 0x0f, 0x62
db 0xab, 0xcd, 0x46, 0x38, 0xb4, 0xde, 0x22, 0x11

kdf_expected_swkey:
db 0xf4, 0x4b, 0x0b, 0x8f, 0x5a, 0x64, 0x94, 0x91
db 0x44, 0x10, 0x2e, 0xdf, 0xa4, 0x8d, 0x35, 0x6b

kdf_expected_a1:
db 0x52, 0xfc, 0x68, 0xb0, 0xfe, 0xe7, 0x03, 0xb3
db 0xe4, 0x9d, 0xcc, 0xdf, 0xd0, 0x0c, 0xb5, 0x80
db 0x43, 0x74, 0x73, 0x96, 0x57, 0xf9, 0xa5, 0x7a
db 0x23, 0x09, 0x82, 0xd9, 0xfe, 0x40, 0x85, 0x92

kdf_expected_iter1:
db 0x62, 0xf0, 0xf1, 0x70, 0xf4, 0x2e, 0x10, 0xb1
db 0x0e, 0x0a, 0x56, 0xa3, 0xf9, 0x82, 0x8e, 0x3d
db 0x78, 0x97, 0xfa, 0x6e, 0x39, 0xbb, 0x53, 0x13
db 0xc2, 0x2b, 0x91, 0x10, 0x91, 0x36, 0x05, 0xbf

kdf_expected_cwiv:
db 0x20, 0xf6, 0x84, 0x84

kdf_expected_swiv:
db 0x4f, 0x2a, 0x11, 0x29

prf_a1_expected:
db 0x7f, 0x10, 0xac, 0xcc, 0x13, 0xae, 0x22, 0x2f
db 0x8d, 0x23, 0x41, 0x33, 0x18, 0x29, 0xd5, 0x0b
db 0x32, 0x07, 0xae, 0x41, 0xf3, 0x9f, 0xe1, 0xdd
db 0x7a, 0x49, 0xb5, 0xad, 0xee, 0x7a, 0xf2, 0xc9

prf_a2_expected:
db 0x6f, 0x45, 0xb9, 0xd9, 0x33, 0x59, 0x71, 0x5e
db 0x8e, 0xd3, 0xde, 0x79, 0xc1, 0x4b, 0x6a, 0x68
db 0x40, 0x3b, 0x6d, 0x78, 0xb0, 0x4f, 0x4d, 0x2e
db 0x1e, 0xfa, 0xd1, 0xb8, 0x36, 0xc4, 0x6d, 0xd7

; AES-CBC test vectors (NIST AES-128-CBC)
aes_key:
db 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6
db 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
aes_iv:
db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
db 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
aes_plain:
db 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96
db 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
aes_expected:
db 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46
db 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d

section .bss
sha256_ctx: resb 104
digest:     resb 32
recv_buf:   resb 4096
prf_out:    resb 64
aes_cipher: resb 16
aes_decrypted: resb 16
cert_buf:   resb 1024
server_resp_buf: resb 2048

section .text
global test_harness

; Build a runtime X.509v3 certificate in the given buffer by copying the
; .rodata template and patching in the RSA modulus at offset 145.
; rdi = output buffer, rsi = pointer to 256-byte RSA modulus n
; Returns rax = certificate length
_build_test_cert:
    push rbx
    push r12
    push r13

    mov rbx, rdi
    mov r12, rsi

    lea rsi, [rel cert_template]
    mov rcx, cert_template_len
    rep movsb

    lea rdi, [rbx + 145]
    mov byte [rdi], 0x00
    inc rdi
    mov rsi, r12
    mov rcx, 256
    rep movsb

    mov rax, cert_template_len
    pop r13
    pop r12
    pop rbx
    ret

; Build a TLS record containing ServerHello + Certificate + ServerHelloDone.
; rdi = output, rsi = cert, edx = cert_len
; Returns rax = total record length
_build_server_resp:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi
    mov r13, rsi
    mov r14d, edx

    ; TLS record header (5 bytes)
    mov byte [r12], 0x16
    mov word [r12 + 1], 0x0303
    ; Payload length (big-endian)
    lea eax, [r14d + 90]
    xchg ah, al
    mov [r12 + 3], ax

    ; ServerHello handshake (76 bytes at [r12+5])
    lea rdi, [r12 + 5]
    mov byte [rdi], 2
    mov byte [rdi + 1], 0
    mov byte [rdi + 2], 0
    mov byte [rdi + 3], 72
    lea rsi, [rel sh_body]
    lea rdi, [rdi + 4]
    mov rcx, 72
    rep movsb

    ; Certificate handshake (at [r12 + CERT_OFFSET_IN_RESP])
    lea rdi, [r12 + CERT_OFFSET_IN_RESP]
    mov byte [rdi], 0x0B

    ; Message length = 6 + cert_len (big-endian, 3 bytes at [rdi+1])
    mov eax, r14d
    add eax, 6
    mov byte [rdi + 3], al
    shr eax, 8
    mov byte [rdi + 2], al
    shr eax, 8
    mov byte [rdi + 1], al

    ; Certificate list length = 3 + cert_len (big-endian, 3 bytes at [rdi+4])
    mov eax, r14d
    add eax, 3
    mov byte [rdi + 6], al
    shr eax, 8
    mov byte [rdi + 5], al
    shr eax, 8
    mov byte [rdi + 4], al

    ; Individual cert length = cert_len (big-endian, 3 bytes at [rdi+7])
    mov eax, r14d
    mov byte [rdi + 9], al
    shr eax, 8
    mov byte [rdi + 8], al
    shr eax, 8
    mov byte [rdi + 7], al

    ; Certificate data at [rdi+10]
    mov rsi, r13
    lea rdi, [rdi + 10]
    mov rcx, r14
    rep movsb

    ; ServerHelloDone at SHD_OFFSET_IN_RESP
    lea rdi, [r12 + SHD_OFFSET_IN_RESP]
    mov dword [rdi], 0x0000000E

    mov eax, RESP_TOTAL_LEN
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Complete server-side handshake after sending ServerHello/Cert/SHD.
; rdi = fd (server end of socketpair)
; rsi = pointer to received ClientHello (with TLS record header)
; edx = total received ClientHello length
_server_finish_handshake:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 320
    ; [rsp+0]:   tls_ctx (118 bytes)
    ; [rsp+128]: recv_iv (16 bytes)
    ; [rsp+144]: mac_in (48 bytes)
    ; [rsp+192]: mac_out (32 bytes)
    ; [rsp+224]: verify_data (16 bytes)
    ; [rsp+240]: plaintext (64 bytes)
    ; [rsp+304]: header_buf (8 bytes)

    mov r12d, edi
    mov r13, rsi
    mov r14d, edx

    lea rdi, [rsp]
    call tls_init

    lea rsi, [r13 + 11]
    lea rdi, [rsp + 18]
    mov rcx, 32
    cld
    rep movsb

    lea rsi, [rel server_resp_buf + 11]
    lea rdi, [rsp + 50]
    mov rcx, 32
    cld
    rep movsb

    lea rdi, [rsp]
    lea rsi, [rel pre_master_sec]
    mov edx, 48
    call tls_derive_keys

    lea rdi, [rel tls_sha256_ctx]
    call sha256_init

    ; Hash ClientHello (skip TLS record header)
    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [r13 + 5]
    lea edx, [r14d - 5]
    call sha256_update

    ; Hash ServerHello (at server_resp_buf + 5, size 76)
    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [rel server_resp_buf + 5]
    mov edx, 76
    call sha256_update

    ; Hash Certificate
    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [rel server_resp_buf + CERT_OFFSET_IN_RESP]
    mov edx, CERT_HASH_LEN
    call sha256_update

    ; Hash ServerHelloDone
    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [rel server_resp_buf + SHD_OFFSET_IN_RESP]
    mov edx, 4
    call sha256_update


    ; ---- Receive CKE ----
    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 5
    call _read_exactly
    test eax, eax
    js .err_cke_read
    cmp byte [rsp + 304], TLS_HANDSHAKE
    jne .err_cke_type

    mov ax, [rsp + 307]
    ror ax, 8
    movzx r15d, ax

    mov edi, r12d
    lea rsi, [rel recv_buf]
    mov edx, r15d
    call _read_exactly
    test eax, eax
    js .sfh_error

    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [rel recv_buf]
    mov edx, r15d
    call sha256_update

    ; ---- Receive CCS ----
    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 5
    call _read_exactly
    test eax, eax
    js .sfh_error
    cmp byte [rsp + 304], TLS_CHANGE_CIPHER_SPEC
    jne .err_css_type

    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 1
    call _read_exactly
    test eax, eax
    js .sfh_error
    cmp byte [rsp + 304], 1
    jne .sfh_error

    ; ---- Receive client Finished (encrypted) ----
    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 5
    call _read_exactly
    test eax, eax
    js .sfh_error
    cmp byte [rsp + 304], TLS_HANDSHAKE
    jne .sfh_error

    mov ax, [rsp + 307]
    ror ax, 8
    movzx r15d, ax

    mov edi, r12d
    lea rsi, [rel recv_buf]
    mov edx, r15d
    call _read_exactly
    test eax, eax
    js .sfh_error

    cmp r15d, 17
    jb .sfh_error

    lea rdi, [rsp + 128]
    lea rsi, [rel recv_buf]
    mov rcx, 16
    cld
    rep movsb

    lea rdi, [rel client_write_key]
    lea rsi, [rsp + 128]
    lea rdx, [rel recv_buf + 16]
    mov ecx, r15d
    sub ecx, 16
    lea r8, [rel recv_buf + 16]
    call aes128_cbc_decrypt

    ; Strip PKCS#7 padding
    mov ecx, r15d
    sub ecx, 16
    lea rsi, [rel recv_buf + 16]
    add rsi, rcx
    dec rsi
    movzx eax, byte [rsi]
    mov eax, 16
    cmp eax, 16
    ja .err_pad_too_long
    test eax, eax
    jz .err_pad_zero
    mov ebx, eax
    sub ecx, ebx
    sub ecx, 32
    js .err_len_underflow
    cmp byte [rel recv_buf + 16], HS_FINISHED
    jne .err_not_finished

    mov edx, ecx
    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [rel recv_buf + 16]
    call sha256_update

    lea rdi, [rel tls_sha256_ctx]
    lea rsi, [rel tls_digest]
    call sha256_final

    ; ---- Compute server Finished verify_data ----
    lea rdi, [rel master_secret]
    mov esi, 48
    lea rdx, [rel sf_label]
    mov ecx, sf_label_len
    lea r8, [rel tls_digest]
    mov r9d, 32
    push 12
    ; Target rsp+224, adjusted for 1 push already done (first push of 12)
    lea rax, [rsp + 224 + 8]
    push rax
    call tls_prf
    add rsp, 16

    ; ---- Send CCS ----
    mov byte [rsp + 304], TLS_CHANGE_CIPHER_SPEC
    mov word [rsp + 305], (3 << 8) | 3
    mov word [rsp + 307], 0x0100
    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 5
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .sfh_error
    mov byte [rsp + 304], 1
    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 1
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .sfh_error

    ; ---- Build and send server Finished (encrypted) ----
    mov byte [rsp + 240], HS_FINISHED
    mov byte [rsp + 241], 0
    mov byte [rsp + 242], 0
    mov byte [rsp + 243], FINISHED_LEN
    ; Matches verify_data location
    lea rsi, [rsp + 224]
    lea rdi, [rsp + 244]
    mov rcx, FINISHED_LEN
    cld
    rep movsb

    mov rax, 2
    bswap rax
    mov qword [rsp + 144], rax
    mov byte [rsp + 152], TLS_HANDSHAKE
    mov word [rsp + 153], (3 << 8) | 3
    mov word [rsp + 155], 0x1000

    lea rdi, [rsp + 157]
    lea rsi, [rsp + 240]
    mov rcx, 16
    cld
    rep movsb

    lea rdi, [rel server_write_mac_key]
    mov rsi, 32
    lea rdx, [rsp + 144]
    mov rcx, 29
    lea r8, [rsp + 192]
    call hmac_sha256

    ; Copy MAC to plaintext buffer after Finished message
    lea rdi, [rsp + 256]
    lea rsi, [rsp + 192]
    mov rcx, 32
    cld
    rep movsb

    lea rdi, [rsp + 240]
    add rdi, 48                 ; Point to end of data payload (16-byte Finished + 32-byte MAC)
    mov ecx, 16                 ; Loop counter for 16 padding bytes
    mov al, 16                  ; PKCS#7 pad value for a 16-byte block (length - 1)
    cld
    rep stosb                   ; Write the 16 padding bytes across the plaintext buffer

    ; 1. Build standard 5-byte TLS Outer Record Header at [rsp + 304]
    mov byte [rsp + 304], TLS_HANDSHAKE
    mov word [rsp + 305], (3 << 8) | 3
    mov word [rsp + 307], 0x5000 ; Total payload length = 80 bytes (16 IV + 64 data) -> Big Endian (0x0050)

    ; 2. Transmit the 5-byte record layer header first
    mov edi, r12d               ; Server socket descriptor (from r12d)
    lea rsi, [rsp + 304]
    mov edx, 5
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .sfh_error

    ; 3. Transmit the 16-byte Explicit IV directly from the stack [rsp + 128]
    mov edi, r12d
    lea rsi, [rsp + 128]        ; IV pointer address
    mov edx, 16
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .sfh_error

    ; 4. Encrypt the plaintext buffer data in-place on the stack
    lea rdi, [rel server_write_key]
    lea rsi, [rsp + 128]        ; IV pointer address
    lea rdx, [rsp + 240]        ; Source buffer payload (plaintext + MAC + Padding)
    mov ecx, 64                 ; Total block data length (48 + 16 padding bytes)
    lea r8, [rsp + 240]         ; Target destination buffer array (encrypt directly in-place)
    call aes128_cbc_encrypt

    ; 5. Transmit the 64-byte encrypted Ciphertext payload straight from the stack
    mov edi, r12d
    lea rsi, [rsp + 240]
    mov edx, 64
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .sfh_error

    xor eax, eax                ; Handshake completely successful! Clear return register
    add rsp, 320
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

.err_cke_read:      
    mov bl, 'A' 
    jmp .sfh_trace_out
.err_cke_type:      
    mov bl, 'B' 
    jmp .sfh_trace_out
.err_css_type:      
    mov bl, 'C' 
    jmp .sfh_trace_out
.err_pad_too_long:  
    mov bl, 'D' 
    jmp .sfh_trace_out
.err_pad_zero:      
    mov bl, 'E' 
    jmp .sfh_trace_out
.err_len_underflow: 
    mov bl, 'F' 
    jmp .sfh_trace_out
.err_not_finished:  
    mov bl, 'G' 
    jmp .sfh_trace_out


.sfh_trace_out:
    ; Store our tracking character byte inside your writable frame array space 
    ; header_buf is at [rsp+304], which is safe to utilize right before unwinding
    mov [rsp + 304], bl
    mov byte [rsp + 305], 10    ; Trailing newline

    ; Fire write(1, [rsp+304], 2) directly via kernel syscall parameters
    mov rax, 1                  ; sys_write
    mov rdi, 1                  ; stdout
    lea rsi, [rsp + 304]        ; buffer pointer
    mov rdx, 2                  ; count
    syscall                     ; Let the kernel print it directly!

.sfh_error:
    mov eax, -1
.sfh_exit:
    add rsp, 320
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

.sfh_pad:
    mov byte [rdi], al
    inc rdi
    dec ecx
    jnz .sfh_pad

.zero_iv:
    lea rdi, [rsp + 128]
    mov esi, 16
    xor edx, edx
    mov eax, 318
    syscall

    lea rdi, [rel server_write_key]
    lea rsi, [rsp + 128]
    lea rdx, [rsp + 240]
    mov ecx, 64
    lea r8, [rsp + 240]
    call aes128_cbc_encrypt

    mov byte [rsp + 304], TLS_HANDSHAKE
    mov word [rsp + 305], (3 << 8) | 3
    mov word [rsp + 307], 0x0050
    mov edi, r12d
    lea rsi, [rsp + 304]
    mov edx, 5
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .sfh_error

    mov edi, r12d
    lea rsi, [rsp + 128]
    mov edx, 16
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .sfh_error

    mov edi, r12d
    lea rsi, [rsp + 240]
    mov edx, 64
    xor ecx, ecx
    call sys_send
    test rax, rax
    js .sfh_error

    xor eax, eax
    jmp .sfh_done

.sfh_done:
    add rsp, 320
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

test_harness:
    push rbx
    sub rsp, 32

    lea rdi, [rsp]
    mov esi, 80
    mov edx, 0x5DB8D822
    call make_sockaddr_in

    mov rdi, 2
    mov rsi, 1
    xor rdx, rdx
    call sys_socket

    call save_errno_and_ret
    cmp eax, -1
    je .socket_failed

    mov ebx, eax

    mov rax, 1
    mov rdi, 1
    lea rsi, [rel sock_ok]
    mov rdx, sock_ok_len
    syscall

    mov edi, ebx
    call sys_close

    add rsp, 32
    pop rbx




    lea rdi, [sha256_ctx]
    call sha256_init

    lea rdi, [sha256_ctx]
    lea rsi, [digest]
    call sha256_final

    lea rsi, [digest]
    lea rdi, [expected_empty]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [sha256_ctx]
    call sha256_init

    lea rdi, [sha256_ctx]
    lea rsi, [test_input]
    mov rdx, test_input_len
    call sha256_update

    lea rdi, [sha256_ctx]
    lea rsi, [digest]
    call sha256_final

    lea rsi, [digest]
    lea rdi, [expected_abc]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail


    lea rdi, [hmac_key1]
    mov rsi, hmac_key1_len
    lea rdx, [hmac_msg1]
    mov rcx, hmac_msg1_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected1]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [hmac_key2]
    mov rsi, hmac_key2_len
    lea rdx, [hmac_msg2]
    mov rcx, hmac_msg2_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected2]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [hmac_key3]
    mov rsi, hmac_key3_len
    lea rdx, [hmac_msg3]
    mov rcx, hmac_msg3_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected3]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [hmac_key4]
    mov rsi, hmac_key4_len
    lea rdx, [hmac_msg4]
    mov rcx, hmac_msg4_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected4]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [hmac_key5]
    mov rsi, hmac_key5_len
    lea rdx, [hmac_msg5]
    mov rcx, hmac_msg5_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected5]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [hmac_key6]
    mov rsi, hmac_key6_len
    lea rdx, [hmac_msg6]
    mov rcx, hmac_msg6_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected6]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [hmac_key7]
    mov rsi, hmac_key7_len
    lea rdx, [hmac_msg7]
    mov rcx, hmac_msg7_len
    lea r8, [digest]
    call hmac_sha256

    lea rsi, [digest]
    lea rdi, [hmac_expected7]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail


    ; --- PRF intermediate value tests ---
    ; Build seed_buf on stack = label + seed
    sub rsp, 128
    lea rdi, [rsp]
    lea rsi, [rel prf_label]
    mov rcx, prf_label_len
    cld
    rep movsb
    lea rsi, [rel prf_seed]
    mov rcx, prf_seed_len
    rep movsb

    ; Compute A(1) = HMAC(secret, seed_buf)
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    mov rdx, rsp
    mov rcx, prf_label_len
    add rcx, prf_seed_len
    lea r8, [rsp + 64]
    call hmac_sha256

    lea rsi, [rsp + 64]
    lea rdi, [rel prf_a1_expected]
    mov ecx, 32
    cld
    repe cmpsb
    jne .prf_abort

    ; Compute A(2) = HMAC(secret, A1)
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    lea rdx, [rsp + 64]
    mov rcx, 32
    lea r8, [rsp + 96]
    call hmac_sha256

    lea rsi, [rsp + 96]
    lea rdi, [rel prf_a2_expected]
    mov ecx, 32
    cld
    repe cmpsb
    jne .prf_abort
    add rsp, 128
    jmp .prf_intermediate_ok

.prf_abort:
    add rsp, 128
    jmp .fail

.prf_intermediate_ok:

    ; --- PRF test ---
    ; --- Direct iteration 1 test ---
    ; This tests: iter1 = HMAC(secret, A(1) + seed_buf)
    sub rsp, 128

    ; Build seed_buf on stack
    lea rdi, [rsp]
    lea rsi, [rel prf_label]
    mov rcx, prf_label_len
    cld
    rep movsb
    lea rsi, [rel prf_seed]
    mov rcx, prf_seed_len
    ; rsp[0..17] = seed_buf
    rep movsb

    ; Compute A(1) = HMAC(secret, seed_buf)
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    mov rdx, rsp
    mov rcx, prf_label_len
    add rcx, prf_seed_len
    ; A(1) at rsp+32
    lea r8, [rsp + 32]
    call hmac_sha256

    ; Build inbuf = A(1) + seed_buf at rsp+64
    lea rdi, [rsp + 64]
    lea rsi, [rsp + 32]
    mov rcx, 32
    rep movsb
    lea rsi, [rsp]
    mov rcx, prf_label_len
    add rcx, prf_seed_len        ; seed_buf_len
    rep movsb

    ; Compute iter1 = HMAC(secret, inbuf)
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    lea rdx, [rsp + 64]
    mov rcx, 32
    add rcx, prf_label_len
    add rcx, prf_seed_len        ; inbuf_len = 32 + seed_buf_len
    ; iter1 at rsp+96
    lea r8, [rsp + 96]
    call hmac_sha256

    ; Compare iter1 with expected first 32 bytes
    lea rsi, [rsp + 96]
    lea rdi, [rel prf_expected_32]
    mov ecx, 32
    cld
    repe cmpsb
    jne .iter1_fail
    add rsp, 128
    jmp .iter1_ok
.iter1_fail:
    add rsp, 128
    jmp .fail
.iter1_ok:

    ; --- PRF 32-byte test via tls_prf ---
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    lea rdx, [rel prf_label]
    mov rcx, prf_label_len
    lea r8, [rel prf_seed]
    mov r9, prf_seed_len
    lea rax, [recv_buf]
    push 32
    push rax
    call tls_prf
    add rsp, 16

    lea rsi, [recv_buf]
    lea rdi, [rel prf_expected_32]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    ; --- PRF 33-byte test via tls_prf ---
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    lea rdx, [rel prf_label]
    mov rcx, prf_label_len
    lea r8, [rel prf_seed]
    mov r9, prf_seed_len
    lea rax, [recv_buf]
    push 33
    push rax
    call tls_prf
    add rsp, 16

    ; Check first 32 bytes
    lea rsi, [recv_buf]
    lea rdi, [rel prf_expected_32]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .fail

    ; --- PRF 48-byte test via tls_prf ---
    lea rdi, [rel prf_secret]
    mov rsi, prf_secret_len
    lea rdx, [rel prf_label]
    mov rcx, prf_label_len
    lea r8, [rel prf_seed]
    mov r9, prf_seed_len
    lea rax, [recv_buf]
    push 48
    push rax
    call tls_prf
    add rsp, 16

    lea rsi, [recv_buf]
    lea rdi, [rel prf_expected_48]
    mov ecx, 48
    cld
    repe cmpsb
    jnz .fail


    ; --- Key derivation test: direct HMAC of seed_buf ---
    sub rsp, 128
    lea rdi, [rsp]
    lea rsi, [rel kdf_master_label]
    mov rcx, 13
    cld
    rep movsb
    lea rsi, [rel kdf_client_random]
    mov rcx, 32
    rep movsb
    lea rsi, [rel kdf_server_random]
    mov rcx, 32
    ; rsp[0..76] = seed_buf
    rep movsb

    ; A(1) = HMAC(pre_master, seed_buf) into recv_buf
    lea rdi, [rel kdf_pre_master]
    mov rsi, kdf_pre_master_len
    mov rdx, rsp
    mov rcx, 77
    lea r8, [recv_buf]
    call hmac_sha256

    lea rsi, [recv_buf]
    lea rdi, [rel kdf_expected_a1]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .kdf_fail

    ; Build inbuf = A(1) + seed_buf at rsp
    lea rdi, [rsp]
    lea rsi, [recv_buf]
    mov rcx, 32
    cld
    rep movsb
    lea rsi, [rel kdf_master_label]
    mov rcx, 13
    rep movsb
    lea rsi, [rel kdf_client_random]
    mov rcx, 32
    rep movsb
    lea rsi, [rel kdf_server_random]
    mov rcx, 32
    ; rsp[0..108] = A(1)+seed_buf
    rep movsb

    ; iter1 = HMAC(pre_master, inbuf) into recv_buf + 32
    lea rdi, [rel kdf_pre_master]
    mov rsi, kdf_pre_master_len
    mov rdx, rsp
    mov rcx, 109
    lea r8, [recv_buf + 32]
    call hmac_sha256

    lea rsi, [recv_buf + 32]
    lea rdi, [rel kdf_expected_iter1]
    mov ecx, 32
    cld
    repe cmpsb
    jnz .kdf_fail

    add rsp, 128
    jmp .kdf_ok
.kdf_fail:
    add rsp, 128
    jmp .fail
.kdf_ok:

    ; --- TLS record layer loopback test ---
    push rbx
    push rbp
    sub rsp, 200
    ; [rsp+0..3]   sv[0], sv[1]
    ; [rsp+8]      tls_ctx (118 bytes)
    ; [rsp+128]    recv_type (1 byte)
    ; [rsp+136]    recv_len (8 bytes)
    ; [rsp+144]    recv_buf (40 bytes)

    ; Create socketpair (AF_UNIX, SOCK_STREAM, 0, sv)
    lea rcx, [rsp]
    mov edi, 1
    mov esi, 1
    xor edx, edx
    call sys_socketpair
    test eax, eax
    jnz .tls_fail

    ; sv[0] write end
    mov ebx, [rsp]
    ; sv[1] read end
    mov ebp, [rsp + 4]

    ; Initialize TLS context
    lea rdi, [rsp + 8]
    call tls_init

    ; Send "abc" as ApplicationData
    lea rdi, [rsp + 8]
    mov esi, ebx
    mov edx, TLS_APPLICATION_DATA
    lea rcx, [test_input]
    mov r8, test_input_len
    call tls_send
    cmp rax, 0
    jl .tls_fail

    ; Receive TLS record via tls_recv
    ; ctx
    lea rdi, [rsp + 8]
    ; fd = sv[1]
    mov esi, ebp
    ; out_type
    lea rdx, [rsp + 128]
    ; out_data
    lea rcx, [rsp + 144]
    ; out_len
    lea r8, [rsp + 136]
    call tls_recv
    test eax, eax
    jnz .tls_fail

    ; Verify content type
    cmp byte [rsp + 128], TLS_APPLICATION_DATA
    jne .tls_fail

    ; Verify data length
    mov rax, [rsp + 136]
    cmp rax, test_input_len
    jne .tls_fail

    ; Verify data content
    lea rsi, [rsp + 144]
    lea rdi, [test_input]
    mov ecx, test_input_len
    cld
    repe cmpsb
    jnz .tls_fail

    ; Cleanup
    mov edi, ebx
    call sys_close
    mov edi, ebp
    call sys_close

    add rsp, 200
    pop rbp
    pop rbx

    ; --- TLS handshake test (fork based loopback) ---
    push rbx
    push rbp
    sub rsp, 144
    ; [rsp+0..3]   sv[0], sv[1]
    ; [rsp+8]      tls_ctx - 118 bytes
    ; [rsp+128]    child status - 4 bytes

    ; Create socketpair
    lea rcx, [rsp]
    mov edi, 1
    mov esi, 1
    xor edx, edx
    call sys_socketpair
    test eax, eax
    jnz .hs_fail

    ; sv[0] client end
    mov ebx, [rsp]
    ; sv[1] server end
    mov ebp, [rsp + 4]

    ; Generate pre-master secret BEFORE fork so child shares it
    mov word [rel pre_master_sec], 0x0303
    lea rdi, [rel pre_master_sec + 2]
    mov esi, 46
    xor edx, edx
    mov eax, 318
    syscall

    ; Build test certificate and server response before fork
    lea rdi, [rel cert_buf]
    lea rsi, [rel rsa_n]
    call _build_test_cert
    lea rdi, [rel server_resp_buf]
    lea rsi, [rel cert_buf]
    mov edx, cert_template_len
    call _build_server_resp

    ; Fork
    ; SYS_fork
    mov eax, 57
    syscall
    test eax, eax
    ; fork failed
    js .hs_fail
    jnz .hs_parent

    ; --- Child process (TLS server) ---
    ; Close client end
    mov edi, ebx
    call sys_close

    ; Receive ClientHello header
    mov edi, ebp
    lea rsi, [recv_buf]
    mov edx, 5
    call _read_exactly
    test eax, eax
    js .hs_fail

    ; Get fragment length from header
    mov ax, [recv_buf + 3]
    ror ax, 8
    movzx r14d, ax

    ; Read fragment body
    mov edi, ebp
    lea rsi, [recv_buf + 5]
    mov edx, r14d
    call _read_exactly
    test eax, eax
    js .hs_fail

    ; Total TLS record length
    lea ebx, [r14d + 5]

    ; Send server response
    mov edi, ebp
    lea rsi, [rel server_resp_buf]
    mov edx, RESP_TOTAL_LEN
    xor ecx, ecx
    call sys_send

    ; Complete server side of handshake (CKE, CCS, Finished exchange)
    mov edi, ebp
    lea rsi, [recv_buf]
    mov edx, ebx
    call _server_finish_handshake

    ; Close and exit
    mov edi, ebp
    call sys_close
    xor edi, edi
    ; SYS_exit
    mov eax, 60
    syscall

.hs_parent:
    ; --- Parent process (TLS client) ---
    ; Close server end
    mov edi, ebp
    call sys_close

    ; Initialize TLS context
    lea rdi, [rsp + 8]
    call tls_init

    ; Run handshake
    ; ctx
    lea rdi, [rsp + 8]
    ; fd
    mov esi, ebx
    ; hostname = NULL
    xor edx, edx
    ; hostlen = 0
    xor ecx, ecx
    call tls_client_start
    test eax, eax
    jnz .hs_fail

    ; Verify handshake completed
    lea rdi, [rsp + 8]
    ; tls_ctx.hs_state
    cmp byte [rdi + 117], HS_DONE
    jne .hs_fail

    ; Verify cipher suite was parsed (TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C)
    lea rdi, [rsp + 8]
    ; tls_ctx.cipher_suite
    mov ax, [rdi + 115]
    cmp ax, 0x003C
    jne .hs_fail

    ; Verify session_id was parsed
    lea rdi, [rsp + 8]
    ; tls_ctx.session_id_len
    cmp byte [rdi + 114], 32
    jne .hs_fail

    ; Wait for child to finish
    ; any child
    mov edi, -1
    ; NULL status
    xor esi, esi
    ; no options
    xor edx, edx
    ; no rusage
    xor r10d, r10d
    ; SYS_wait4
    mov eax, 61
    syscall

    ; Cleanup
    mov edi, ebx
    call sys_close

    add rsp, 144
    pop rbp
    pop rbx
    jmp .after_hs

.hs_fail:
    add rsp, 144
    pop rbp
    pop rbx
    jmp .fail

.tls_fail:
    add rsp, 200
    pop rbp
    pop rbx
    jmp .fail

.after_hs:

    ; --- TLS connect/disconnect integration test ---
    push rbx
    push rbp
    sub rsp, 144

    lea rcx, [rsp]
    mov edi, 1
    mov esi, 1
    xor edx, edx
    call sys_socketpair
    test eax, eax
    jnz .conn_int_fail

    mov ebx, [rsp]
    mov ebp, [rsp + 4]

    ; Generate pre-master secret BEFORE fork so child shares it
    mov word [rel pre_master_sec], 0x0303
    lea rdi, [rel pre_master_sec + 2]
    mov esi, 46
    xor edx, edx
    mov eax, 318
    syscall

    ; Build test certificate and server response before fork
    lea rdi, [rel cert_buf]
    lea rsi, [rel rsa_n]
    call _build_test_cert
    lea rdi, [rel server_resp_buf]
    lea rsi, [rel cert_buf]
    mov edx, cert_template_len
    call _build_server_resp

    mov eax, 57
    syscall
    test eax, eax
    js .conn_int_fail
    jnz .conn_int_parent

    ; --- Child (TLS server) ---
    mov edi, ebx
    call sys_close

    ; Recv ClientHello header
    mov edi, ebp
    lea rsi, [recv_buf]
    mov edx, 5
    call _read_exactly
    test eax, eax
    js .conn_int_fail

    ; Get fragment length
    mov ax, [recv_buf + 3]
    ror ax, 8
    movzx r14d, ax

    ; Read fragment body
    mov edi, ebp
    lea rsi, [recv_buf + 5]
    mov edx, r14d
    call _read_exactly
    test eax, eax
    js .conn_int_fail

    ; Total TLS record length
    lea ebx, [r14d + 5]

    ; Send server_resp (ServerHello + Cert + SHD)
    mov edi, ebp
    lea rsi, [rel server_resp_buf]
    mov edx, RESP_TOTAL_LEN
    xor ecx, ecx
    call sys_send

    ; Complete server side of handshake
    mov edi, ebp
    lea rsi, [recv_buf]
    mov edx, ebx
    call _server_finish_handshake

    ; Close and exit
    mov edi, ebp
    call sys_close
    xor edi, edi
    mov eax, 60
    syscall

.conn_int_parent:
    mov edi, ebp
    call sys_close

    ; tls_connect initializes context and runs handshake
    lea rdi, [rsp + 8]
    mov esi, ebx
    xor edx, edx
    xor ecx, ecx
    call tls_connect
    test eax, eax
    jnz .conn_int_fail

    ; Verify handshake completed
    cmp byte [rsp + 8 + 117], HS_DONE
    jne .conn_int_fail

    ; Verify cipher suite parsed
    mov ax, [rsp + 8 + 115]
    cmp ax, 0x003C
    jne .conn_int_fail

    ; tls_disconnect sends close_notify and closes fd
    lea rdi, [rsp + 8]
    mov esi, ebx
    call tls_disconnect

    ; Wait for child
    mov edi, -1
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall

    add rsp, 144
    pop rbp
    pop rbx
    jmp .conn_int_done

.conn_int_fail:
    add rsp, 144
    pop rbp
    pop rbx
    jmp .fail

.conn_int_done:

    ; --- AES-CBC encrypt/decrypt round-trip test ---
    lea rdi, [rel aes_key]
    lea rsi, [rel aes_iv]
    lea rdx, [rel aes_plain]
    mov rcx, 16
    lea r8, [rel aes_cipher]
    call aes128_cbc_encrypt

    lea rsi, [rel aes_cipher]
    lea rdi, [rel aes_expected]
    mov ecx, 16
    cld
    repe cmpsb
    jnz .fail

    lea rdi, [rel aes_key]
    lea rsi, [rel aes_iv]
    lea rdx, [rel aes_cipher]
    mov rcx, 16
    lea r8, [rel aes_decrypted]
    call aes128_cbc_decrypt

    lea rsi, [rel aes_decrypted]
    lea rdi, [rel aes_plain]
    mov ecx, 16
    cld
    repe cmpsb
    jnz .fail

    ; --- Encrypted TLS record test: build encrypted record in memory ---
    ; Set up TLS context and derive keys
    sub rsp, 224
    ; [rsp+0] tls_ctx (118 bytes)
    ; [rsp+128] MAC output (32 bytes)
    ; [rsp+160] padded plaintext (64 bytes)

    lea rdi, [rsp]
    call tls_init

    lea rsi, [rel kdf_client_random]
    lea rdi, [rsp + 18]
    mov rcx, 32
    cld
    rep movsb

    lea rsi, [rel kdf_server_random]
    lea rdi, [rsp + 50]
    mov rcx, 32
    cld
    rep movsb

    lea rdi, [rsp]
    lea rsi, [rel kdf_pre_master]
    mov rdx, kdf_pre_master_len
    call tls_derive_keys

    mov byte [rsp + 117], HS_DONE

    ; Build mac_input at rsp+160 (seq||type||ver||len||frag)
    xor eax, eax
    ; seq_num = 0 (8 bytes)
    mov qword [rsp + 160], 0
    mov byte [rsp + 168], TLS_APPLICATION_DATA
    ; version major = 3
    mov byte [rsp + 169], 3
    ; version minor = 3
    mov byte [rsp + 170], 3
    ; fragment length high
    mov byte [rsp + 171], 0
    ; fragment length low
    mov byte [rsp + 172], 3
    mov byte [rsp + 173], 'a'
    mov byte [rsp + 174], 'b'
    mov byte [rsp + 175], 'c'

    ; HMAC-SHA256(client_write_mac_key, 32, mac_input, 16, MAC_out at [rsp+128])
    lea rdi, [rel client_write_mac_key]
    mov rsi, 32
    lea rdx, [rsp + 160]
    mov rcx, 16
    lea r8, [rsp + 128]
    call hmac_sha256

    ; Build padded plaintext at rsp+160
    ; fragment "abc"
    mov byte [rsp + 160], 'a'
    mov byte [rsp + 161], 'b'
    mov byte [rsp + 162], 'c'

    ; Copy 32-byte MAC from rsp+128 to rsp+163
    lea rdi, [rsp + 163]
    lea rsi, [rsp + 128]
    mov rcx, 32
    cld
    rep movsb

    ; PKCS#7 padding: pad to 48 bytes (next multiple of 16 after 35)
    ; 48 - 35 = 13 bytes of 0x0d
    mov ecx, 13
    mov al, 13
.enc_pad:
    mov byte [rsp + 163 + 32 + rcx - 1], al
    dec ecx
    jnz .enc_pad

    ; Encrypt with AES-128-CBC
    ; Generate a dummy IV (16 bytes of zeros)
    xor eax, eax
    ; reuse rsp+128 as IV area
    mov qword [rsp + 128], rax
    mov qword [rsp + 136], rax

    lea rdi, [rel client_write_key]
    ; IV
    lea rsi, [rsp + 128]
    ; plaintext (48 bytes)
    lea rdx, [rsp + 160]
    mov rcx, 48
    ; ciphertext output (in-place)
    lea r8, [rsp + 160]
    call aes128_cbc_encrypt

    ; Decrypt with AES-128-CBC
    lea rdi, [rel client_write_key]
    ; same IV
    lea rsi, [rsp + 128]
    ; ciphertext
    lea rdx, [rsp + 160]
    mov rcx, 48
    ; decrypted output (reuse IV area)
    lea r8, [rsp + 128]
    call aes128_cbc_decrypt

    ; Strip padding: last byte = pad value
    lea rsi, [rsp + 128]
    add rsi, 48
    dec rsi
    ; pad_value
    movzx eax, byte [rsi]
    mov ecx, eax
    sub ecx, 48
    ; ecx = unpadded length
    neg ecx

    ; Verify unpadded length = 35 (3 fragment + 32 MAC)
    cmp ecx, 35
    jne .enc_fail

    ; Verify fragment "abc" (first 3 bytes)
    ; "ab"
    cmp word [rsp + 128], 0x6261
    jne .enc_fail
    ; "c"
    cmp byte [rsp + 130], 0x63
    jne .enc_fail

    add rsp, 224
    jmp .tls_pass

.enc_fail:
    add rsp, 224
    jmp .fail

.tls_pass:

    ; --- X.509 Certificate parser test ---
    lea rdi, [rel cert_buf]
    mov esi, cert_template_len
    call x509_parse_cert
    test eax, eax
    jnz .fail

    ; Verify dates were parsed
    cmp dword [rel cert_not_before], 0
    je .fail
    cmp dword [rel cert_not_after], 0
    je .fail
    mov eax, [rel cert_not_before]
    cmp eax, [rel cert_not_after]
    jae .fail

    ; Verify pubkey was extracted
    cmp word [rel server_pubkey_n_len], 0
    je .fail
    cmp word [rel server_pubkey_e_len], 0
    je .fail

    ; Verify certificate validity
    call x509_check_validity
    test eax, eax
    jnz .fail

    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg_pass]
    mov rdx, msg_pass_len
    syscall
    jmp .done

.socket_failed:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel sock_fail]
    mov rdx, sock_fail_len
    syscall
    add rsp, 32
    pop rbx
    jmp .done

.fail:
    ; Save the error code (currently in EAX or RAX) into RDI as our exit status
    mov edi, eax                ; Lower 32-bit error code becomes the exit code
    and edi, 0xFF               ; Keep only the lowest byte for Linux shell bounds

    ; Execute sys_exit (syscall 60) immediately to return the true error code
    mov rax, 60                 ; sys_exit syscall number
    syscall                     ; Exit immediately! The shell will catch the value.


.done:
    ret
