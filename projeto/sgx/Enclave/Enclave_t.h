#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ecall_generate_and_seal_key(uint8_t* sealed_data, uint32_t sealed_size);
sgx_status_t ecall_unseal_key(uint8_t* sealed_data, uint32_t sealed_size);
sgx_status_t ecall_verify_signature(const char* message, uint8_t* signature, int signer_type, int* is_valid);
sgx_status_t ecall_process_stats(const char* signed_data, uint32_t signed_data_len, uint8_t* signature_bin, int signer_type, uint8_t* ciphertext, uint32_t ciphertext_len, uint8_t* iv, uint32_t iv_len, uint8_t* mac, int op_code, double* result, uint8_t* pubkey_pem, uint32_t pubkey_len);
sgx_status_t ecall_encrypt_data(uint8_t* plaintext, size_t plaintext_len, uint8_t* iv, size_t iv_len, uint8_t* ciphertext, uint8_t* mac);
sgx_status_t ecall_generate_iv(uint8_t* iv, size_t iv_len);
sgx_status_t ecall_sum(double* data, size_t len, double* result);
sgx_status_t ecall_mean(double* data, size_t len, double* result);
sgx_status_t ecall_min(double* data, size_t len, double* result);
sgx_status_t ecall_max(double* data, size_t len, double* result);
sgx_status_t ecall_median(double* data, size_t len, double* result);
sgx_status_t ecall_mode(double* data, size_t len, double* result);
sgx_status_t ecall_variance(double* data, size_t len, double* result);
sgx_status_t ecall_stddev(double* data, size_t len, double* result);

sgx_status_t SGX_CDECL ocall_printf(const char* str);
sgx_status_t SGX_CDECL ocall_request_authorization(const char* msg, int* authorized);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(void* waiter, void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(void* waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
